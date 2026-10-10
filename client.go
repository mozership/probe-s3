package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/linyows/probe/actionrpc"
)

// maxRedirects is how many times a request is sent again to where the
// storage points, as for a bucket of another region.
const maxRedirects = 5

// maxBody is the most of an object that res.body holds. The digest in
// res.sha256 is of the whole object, however large.
const maxBody = 1 << 20

// maxAnswer is the most that is read of an answer that is not an object: a
// list of keys or an error.
const maxAnswer = 8 << 20

// guarded sends a request only to a host the guard allows. Every request
// the action sends goes through it, a redirected one included, so that
// nothing is connected to around the guard.
type guarded struct {
	base  http.RoundTripper
	guard actionrpc.Guard
}

func (g *guarded) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := checkHost(g.guard, req.URL); err != nil {
		return nil, err
	}
	return g.base.RoundTrip(req)
}

// checkHost returns a Refused error when the guard does not allow the host
// of u. A host without a port is taken at the port of its scheme.
func checkHost(guard actionrpc.Guard, u *url.URL) error {
	host := u.Host
	if u.Port() == "" {
		port := "80"
		if u.Scheme == "https" {
			port = "443"
		}
		host = net.JoinHostPort(u.Hostname(), port)
	}
	return guard.CheckHost(host)
}

// payload is the body of a put. It is opened anew each time the request is
// sent, as a redirected request is sent again.
type payload struct {
	sha256 string
	size   int64
	open   func() (io.ReadCloser, error)
}

// payload returns what the request sends: the body of a put, hashed before
// anything is sent as the signature covers its digest, and nothing for any
// other operation.
func (r *request) payload() (*payload, error) {
	if r.op != opPut {
		return &payload{sha256: emptySHA256, open: func() (io.ReadCloser, error) { return http.NoBody, nil }}, nil
	}
	if r.file == "" {
		return &payload{
			sha256: hexSHA256(r.body),
			size:   int64(len(r.body)),
			open: func() (io.ReadCloser, error) {
				// An empty body is said to be none, or it would be sent
				// without its length.
				if len(r.body) == 0 {
					return http.NoBody, nil
				}
				return io.NopCloser(bytes.NewReader(r.body)), nil
			},
		}, nil
	}

	f, err := os.Open(r.file)
	if err != nil {
		return nil, fmt.Errorf("with.file: %w", err)
	}
	defer func() { _ = f.Close() }()
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("with.file: %s is not a file", r.file)
	}
	h := sha256.New()
	size, err := io.Copy(h, f)
	if err != nil {
		return nil, fmt.Errorf("with.file: %w", err)
	}
	return &payload{
		sha256: hex.EncodeToString(h.Sum(nil)),
		size:   size,
		open: func() (io.ReadCloser, error) {
			if size == 0 {
				return http.NoBody, nil
			}
			return os.Open(r.file)
		},
	}, nil
}

// target returns the URL the operation is addressed to in region: the
// bucket in the host, or, addressed by path, in front of the key.
func (r *request) target(region string) *url.URL {
	u := &url.URL{Scheme: "https", Host: awsHost(region)}
	if r.endpoint != nil {
		u = &url.URL{Scheme: r.endpoint.Scheme, Host: r.endpoint.Host, Path: r.endpoint.Path}
	}
	if r.pathStyle {
		u.Path += "/" + r.bucket
	} else {
		u.Host = r.bucket + "." + u.Host
	}

	q := url.Values{}
	if r.op == opList {
		u.Path += "/"
		q.Set("list-type", "2")
		// Keys come encoded, so that one with a character XML cannot carry
		// is read as it is.
		q.Set("encoding-type", "url")
		if r.key != "" {
			q.Set("prefix", r.key)
		}
		if r.maxKeys > 0 {
			q.Set("max-keys", strconv.Itoa(r.maxKeys))
		}
	} else {
		u.Path += "/" + r.key
	}
	// The path and the query are written the way they are signed, and Go
	// sends them as written.
	u.RawPath = uriEncode(u.Path, false)
	u.RawQuery = canonicalQuery(q)
	return u
}

// awsHost is where S3 is served in region.
func awsHost(region string) string {
	if strings.HasPrefix(region, "cn-") {
		return "s3." + region + ".amazonaws.com.cn"
	}
	return "s3." + region + ".amazonaws.com"
}

func (r *request) method() string {
	switch r.op {
	case opHead:
		return http.MethodHead
	case opPut:
		return http.MethodPut
	case opDelete:
		return http.MethodDelete
	}
	return http.MethodGet
}

func (a *Action) do(r *request, guard actionrpc.Guard) (map[string]any, error) {
	// Under read-only nothing of a put is read, a file included; the step
	// was refused before it came here.
	body, err := r.payload()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	if r.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.timeout)
		defer cancel()
	}

	base := a.transport
	if base == nil {
		base = http.DefaultTransport
	}
	client := &http.Client{
		Transport: &guarded{base: base, guard: guard},
		// A redirect is followed here rather than by the client, as the
		// request has to be signed again for the host it goes to.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	start := time.Now()
	region := r.region
	target := r.target(region)
	for hop := 0; ; hop++ {
		resp, err := a.send(ctx, client, r, target, region, body)
		if err != nil {
			// A host the guard refused is a refusal, not a failure to
			// reach the storage.
			if refused := (*actionrpc.Refused)(nil); errors.As(err, &refused) {
				return nil, refused
			}
			if ctx.Err() != nil {
				return nil, fmt.Errorf("s3 %s timed out after %s", r.op, r.timeout)
			}
			return nil, err
		}

		next, nextRegion, ok := r.redirect(resp, target, region)
		if !ok {
			defer func() { _ = resp.Body.Close() }()
			res, err := r.read(resp)
			if err != nil {
				if ctx.Err() != nil {
					return nil, fmt.Errorf("s3 %s timed out after %s", r.op, r.timeout)
				}
				return nil, err
			}
			return r.result(target, region, body, res, time.Since(start)), nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxAnswer))
		_ = resp.Body.Close()
		if hop >= maxRedirects {
			return nil, fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		target, region = next, nextRegion
	}
}

// send signs the operation for target and region, and sends it.
func (a *Action) send(ctx context.Context, client *http.Client, r *request, target *url.URL, region string, body *payload) (*http.Response, error) {
	rc, err := body.open()
	if err != nil {
		return nil, fmt.Errorf("with.file: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, r.method(), target.String(), rc)
	if err != nil {
		_ = rc.Close()
		return nil, err
	}
	req.ContentLength = body.size
	if r.contentType != "" {
		req.Header.Set("Content-Type", r.contentType)
	}
	for k, v := range r.metadata {
		req.Header.Set("X-Amz-Meta-"+k, v)
	}

	now := time.Now
	if a.now != nil {
		now = a.now
	}
	sign(req, r.creds, region, body.sha256, now())

	req.Header.Set("User-Agent", "probe-s3/"+version)
	// The object is taken as it is stored: asked for nothing else, Go would
	// ask for gzip and undo it, and the digest would be of other bytes.
	req.Header.Set("Accept-Encoding", "identity")
	return client.Do(req)
}

// redirect tells where the storage points the request to, when it does:
// the Location it answers with, or, on AWS, the region it names for a
// bucket that is not in the one the request was signed for. A Location
// that leaves the storage is not followed, and the redirect is the result.
func (r *request) redirect(resp *http.Response, target *url.URL, region string) (*url.URL, string, bool) {
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
	default:
		return nil, "", false
	}
	if named := resp.Header.Get("X-Amz-Bucket-Region"); regionName.MatchString(named) {
		region = named
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		next, err := target.Parse(loc)
		if err != nil || (next.Scheme != "http" && next.Scheme != "https") || !r.within(next) {
			return nil, "", false
		}
		return next, region, true
	}
	if r.endpoint == nil && region != r.region {
		if next := r.target(region); next.String() != target.String() {
			return next, region, true
		}
	}
	return nil, "", false
}

// within reports whether u is served by the storage the request went to:
// AWS, or the host of the endpoint and the names under it. A request signed
// again for anywhere else would carry the session token there.
func (r *request) within(u *url.URL) bool {
	host := strings.ToLower(u.Hostname())
	if r.endpoint == nil {
		return strings.HasSuffix(host, ".amazonaws.com") || strings.HasSuffix(host, ".amazonaws.com.cn")
	}
	base := strings.ToLower(r.endpoint.Hostname())
	return host == base || strings.HasSuffix(host, "."+base)
}

// answer is what the storage answered, as the result shows it.
type answer struct {
	code    int
	status  string
	headers http.Header
	fields  map[string]any
}

// read reads the answer to the operation. An answer that is not a success
// carries an error in XML, except to a head, which has no body.
func (r *request) read(resp *http.Response) (*answer, error) {
	res := &answer{code: resp.StatusCode, status: resp.Status, headers: resp.Header, fields: map[string]any{}}
	res.fields["error_code"] = ""
	res.fields["error_message"] = ""

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer))
		if err != nil {
			return nil, err
		}
		var e struct {
			Code    string `xml:"Code"`
			Message string `xml:"Message"`
		}
		if xml.Unmarshal(raw, &e) == nil {
			res.fields["error_code"] = e.Code
			res.fields["error_message"] = e.Message
		}
		return res, nil
	}

	switch r.op {
	case opGet:
		readObjectHeaders(res, resp)
		if err := readObject(res, resp); err != nil {
			return nil, err
		}
	case opHead:
		readObjectHeaders(res, resp)
	case opPut:
		res.fields["etag"] = unquote(resp.Header.Get("ETag"))
	case opList:
		if err := readList(res, resp); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// readObjectHeaders reads what the headers of a get or a head tell of the
// object.
func readObjectHeaders(res *answer, resp *http.Response) {
	res.fields["etag"] = unquote(resp.Header.Get("ETag"))
	res.fields["size"] = max(resp.ContentLength, 0)
	res.fields["content_type"] = resp.Header.Get("Content-Type")
	res.fields["last_modified"] = ""
	if t, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		res.fields["last_modified"] = t.UTC().Format(time.RFC3339)
	}
	metadata := map[string]any{}
	for name, v := range resp.Header {
		if key, ok := strings.CutPrefix(strings.ToLower(name), "x-amz-meta-"); ok {
			metadata[key] = strings.Join(v, ", ")
		}
	}
	res.fields["metadata"] = metadata
}

// readObject reads the object of a get: all of it into the digest, and its
// first maxBody bytes into the body, when they are text.
func readObject(res *answer, resp *http.Response) error {
	h := sha256.New()
	var head bytes.Buffer
	size, err := io.Copy(h, io.TeeReader(resp.Body, &limitedWriter{w: &head, n: maxBody}))
	if err != nil {
		return err
	}
	res.fields["size"] = size
	res.fields["sha256"] = hex.EncodeToString(h.Sum(nil))
	res.fields["truncated"] = size > maxBody

	text := head.Bytes()
	if size > maxBody {
		// The cut may fall inside a character, which is left out.
		for i := 0; i < utf8.UTFMax && len(text) > 0 && !utf8.Valid(text); i++ {
			text = text[:len(text)-1]
		}
	}
	res.fields["binary"] = !utf8.Valid(text)
	res.fields["body"] = ""
	if !utf8.Valid(text) {
		return nil
	}
	res.fields["body"] = string(text)
	// A JSON object is parsed, as the http action parses a JSON response.
	if size <= maxBody && strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "json") {
		var parsed any
		if json.Unmarshal(text, &parsed) == nil {
			res.fields["body"] = parsed
			res.fields["rawbody"] = string(text)
		}
	}
	return nil
}

// limitedWriter writes the first n bytes it is given to w, and drops the
// rest without an error.
type limitedWriter struct {
	w io.Writer
	n int
}

func (l *limitedWriter) Write(p []byte) (int, error) {
	if keep := min(len(p), l.n); keep > 0 {
		if _, err := l.w.Write(p[:keep]); err != nil {
			return 0, err
		}
		l.n -= keep
	}
	return len(p), nil
}

// readList reads the keys a list answered with.
func readList(res *answer, resp *http.Response) error {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAnswer+1))
	if err != nil {
		return err
	}
	if len(raw) > maxAnswer {
		return fmt.Errorf("the list is larger than %d bytes; narrow it with a prefix or with.max_keys", maxAnswer)
	}
	var list struct {
		IsTruncated  bool   `xml:"IsTruncated"`
		EncodingType string `xml:"EncodingType"`
		Contents     []struct {
			Key          string `xml:"Key"`
			Size         int64  `xml:"Size"`
			ETag         string `xml:"ETag"`
			LastModified string `xml:"LastModified"`
		} `xml:"Contents"`
	}
	if err := xml.Unmarshal(raw, &list); err != nil {
		return fmt.Errorf("the list cannot be read: %w", err)
	}

	objects := make([]any, 0, len(list.Contents))
	for _, c := range list.Contents {
		key := c.Key
		if list.EncodingType == "url" {
			if decoded, err := url.QueryUnescape(key); err == nil {
				key = decoded
			}
		}
		modified := c.LastModified
		if t, err := time.Parse(time.RFC3339Nano, modified); err == nil {
			modified = t.UTC().Format(time.RFC3339)
		}
		objects = append(objects, map[string]any{
			"key":           key,
			"size":          c.Size,
			"etag":          unquote(c.ETag),
			"last_modified": modified,
		})
	}
	res.fields["objects"] = objects
	res.fields["count"] = len(objects)
	res.fields["truncated"] = list.IsTruncated
	return nil
}

// unquote takes the quotes off an ETag.
func unquote(etag string) string {
	return strings.Trim(strings.TrimPrefix(etag, "W/"), `"`)
}

// result returns what the step sees. Its status is 0 when the storage
// answered with a 2xx.
func (r *request) result(target *url.URL, region string, body *payload, res *answer, rt time.Duration) map[string]any {
	req := map[string]any{
		"operation":  r.op,
		"bucket":     r.bucket,
		"region":     region,
		"endpoint":   "",
		"path_style": r.pathStyle,
		"url":        target.String(),
		"signed":     !r.creds.anonymous(),
	}
	if r.endpoint != nil {
		req["endpoint"] = r.endpoint.String()
	}
	switch r.op {
	case opList:
		req["prefix"] = r.key
		req["max_keys"] = r.maxKeys
	case opPut:
		req["key"] = r.key
		req["body"] = r.written
		req["file"] = r.file
		req["content_type"] = r.contentType
		metadata := make(map[string]any, len(r.metadata))
		for k, v := range r.metadata {
			metadata[k] = v
		}
		req["metadata"] = metadata
		req["size"] = body.size
		req["sha256"] = body.sha256
	default:
		req["key"] = r.key
	}

	out := map[string]any{
		"code":    res.code,
		"status":  res.status,
		"headers": flattenHeaders(res.headers),
	}
	for k, v := range res.fields {
		out[k] = v
	}

	status := 0
	if res.code < 200 || res.code > 299 {
		status = 1
	}
	return map[string]any{
		"req":    req,
		"res":    out,
		"rt":     rt.String(),
		"status": status,
	}
}

func flattenHeaders(h http.Header) map[string]any {
	m := make(map[string]any, len(h))
	for k, v := range h {
		m[k] = strings.Join(v, ", ")
	}
	return m
}
