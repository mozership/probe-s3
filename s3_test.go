package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/linyows/probe/actionref"
	"github.com/linyows/probe/actionrpc"
)

// object is what the stand-in for S3 keeps for a key.
type object struct {
	body        []byte
	contentType string
	metadata    map[string]string
	modified    time.Time
}

// storage stands in for S3, addressed by path. It keeps the objects it is
// sent, and records every request it gets.
type storage struct {
	mu       sync.Mutex
	objects  map[string]*object
	requests []*http.Request
	// answer, when set, answers a request in place of the storage, unless
	// it returns false.
	answer func(w http.ResponseWriter, r *http.Request) bool
}

func newStorage(t *testing.T) (*storage, string) {
	t.Helper()
	s := &storage{objects: map[string]*object{}}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	return s, ts.URL
}

func (s *storage) put(key, body, contentType string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = &object{body: []byte(body), contentType: contentType, modified: time.Date(2026, 10, 10, 1, 2, 3, 0, time.UTC)}
}

func (s *storage) got() []*http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests)
}

func fail(w http.ResponseWriter, code int, name, message string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(code)
	_, _ = fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?><Error><Code>%s</Code><Message>%s</Message></Error>`, name, message)
}

func (s *storage) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	s.mu.Lock()
	rec := r.Clone(r.Context())
	rec.Body = io.NopCloser(bytes.NewReader(body))
	s.requests = append(s.requests, rec)
	answer := s.answer
	s.mu.Unlock()
	if answer != nil && answer(w, r) {
		return
	}

	bucket, key, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if bucket != "fixtures" {
		fail(w, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if key == "" && r.Method == http.MethodGet {
		s.list(w, r)
		return
	}
	switch r.Method {
	case http.MethodPut:
		o := &object{body: body, contentType: r.Header.Get("Content-Type"), metadata: map[string]string{}, modified: time.Date(2026, 10, 10, 1, 2, 3, 0, time.UTC)}
		for name, v := range r.Header {
			if k, ok := strings.CutPrefix(strings.ToLower(name), "x-amz-meta-"); ok {
				o.metadata[k] = v[0]
			}
		}
		s.objects[key] = o
		w.Header().Set("ETag", `"`+etag(body)+`"`)
	case http.MethodDelete:
		delete(s.objects, key)
		w.WriteHeader(http.StatusNoContent)
	case http.MethodGet, http.MethodHead:
		o, ok := s.objects[key]
		if !ok {
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			fail(w, http.StatusNotFound, "NoSuchKey", "The specified key does not exist.")
			return
		}
		w.Header().Set("ETag", `"`+etag(o.body)+`"`)
		w.Header().Set("Content-Type", o.contentType)
		w.Header().Set("Content-Length", strconv.Itoa(len(o.body)))
		w.Header().Set("Last-Modified", o.modified.Format(http.TimeFormat))
		for k, v := range o.metadata {
			w.Header().Set("X-Amz-Meta-"+k, v)
		}
		if r.Method == http.MethodGet {
			_, _ = w.Write(o.body)
		}
	default:
		fail(w, http.StatusMethodNotAllowed, "MethodNotAllowed", "The specified method is not allowed")
	}
}

func (s *storage) list(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	limit := 1000
	if v := q.Get("max-keys"); v != "" {
		limit, _ = strconv.Atoi(v)
	}
	var keys []string
	for k := range s.objects {
		if strings.HasPrefix(k, q.Get("prefix")) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	truncated := len(keys) > limit
	if truncated {
		keys = keys[:limit]
	}

	type contents struct {
		Key          string
		LastModified string
		ETag         string
		Size         int
	}
	out := struct {
		XMLName      xml.Name `xml:"ListBucketResult"`
		IsTruncated  bool
		EncodingType string
		Contents     []contents
	}{IsTruncated: truncated, EncodingType: q.Get("encoding-type")}
	for _, k := range keys {
		o := s.objects[k]
		name := k
		if out.EncodingType == "url" {
			name = url.QueryEscape(k)
		}
		out.Contents = append(out.Contents, contents{Key: name, LastModified: o.modified.Format("2006-01-02T15:04:05.000Z"), ETag: `"` + etag(o.body) + `"`, Size: len(o.body)})
	}
	w.Header().Set("Content-Type", "application/xml")
	_ = xml.NewEncoder(w).Encode(out)
}

func etag(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:16])
}

// action returns an Action that reads no environment of the machine the
// tests run on.
func action() *Action {
	return &Action{getenv: func(string) string { return "" }}
}

// with returns the parameters of a step against the stand-in at endpoint,
// with extra laid over them.
func with(endpoint string, extra map[string]any) map[string]any {
	m := map[string]any{
		"bucket":            "fixtures",
		"endpoint":          endpoint,
		"access_key_id":     "AKIDEXAMPLE",
		"secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
	}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

func run(t *testing.T, a *Action, w map[string]any) (map[string]any, map[string]any) {
	t.Helper()
	ret, err := a.Run(w)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	return ret["req"].(map[string]any), ret["res"].(map[string]any)
}

func TestPutGetHeadListDelete(t *testing.T) {
	s, endpoint := newStorage(t)
	a := action()

	req, res := run(t, a, with(endpoint, map[string]any{
		"put":          "reports/2026 Q3/summary.txt",
		"body":         "hello, bucket\n",
		"content_type": "text/plain; charset=utf-8",
		"metadata":     map[string]any{"Owner": "probe", "run": 7},
	}))
	sum := hexSHA256([]byte("hello, bucket\n"))
	if res["code"] != 200 || res["etag"] != etag([]byte("hello, bucket\n")) {
		t.Errorf("put res = %v", res)
	}
	if req["operation"] != "put" || req["key"] != "reports/2026 Q3/summary.txt" || req["sha256"] != sum || req["size"] != int64(14) || req["signed"] != true {
		t.Errorf("put req = %v", req)
	}
	if want := endpoint + "/fixtures/reports/2026%20Q3/summary.txt"; req["url"] != want {
		t.Errorf("put req.url = %v, want %s", req["url"], want)
	}

	sent := s.got()[0]
	if sent.Method != http.MethodPut || sent.Header.Get("X-Amz-Content-Sha256") != sum || sent.Header.Get("X-Amz-Meta-Owner") != "probe" || sent.Header.Get("X-Amz-Meta-Run") != "7" {
		t.Errorf("put sent %s with %v", sent.Method, sent.Header)
	}
	auth := sent.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/") || !strings.Contains(auth, "/us-east-1/s3/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-meta-owner;x-amz-meta-run, Signature=") {
		t.Errorf("Authorization = %q", auth)
	}
	if got := sent.Header.Get("User-Agent"); got != "probe-s3/dev" {
		t.Errorf("User-Agent = %q", got)
	}

	_, res = run(t, a, with(endpoint, map[string]any{"get": "reports/2026 Q3/summary.txt"}))
	want := map[string]any{
		"code": 200, "body": "hello, bucket\n", "sha256": sum, "size": int64(14),
		"content_type": "text/plain; charset=utf-8", "last_modified": "2026-10-10T01:02:03Z",
		"etag": etag([]byte("hello, bucket\n")), "truncated": false, "binary": false,
		"error_code": "", "error_message": "",
	}
	for k, v := range want {
		if !reflect.DeepEqual(res[k], v) {
			t.Errorf("get res.%s = %#v, want %#v", k, res[k], v)
		}
	}
	if got := res["metadata"]; !reflect.DeepEqual(got, map[string]any{"owner": "probe", "run": "7"}) {
		t.Errorf("get res.metadata = %v", got)
	}

	_, res = run(t, a, with(endpoint, map[string]any{"head": "reports/2026 Q3/summary.txt"}))
	if res["code"] != 200 || res["size"] != int64(14) || res["etag"] != want["etag"] || res["last_modified"] != want["last_modified"] {
		t.Errorf("head res = %v", res)
	}
	if _, ok := res["body"]; ok {
		t.Errorf("head res has a body: %v", res["body"])
	}

	s.put("reports/a+b.txt", "ab", "text/plain")
	s.put("other.txt", "x", "text/plain")
	req, res = run(t, a, with(endpoint, map[string]any{"list": "reports/"}))
	if req["prefix"] != "reports/" || res["code"] != 200 || res["count"] != 2 || res["truncated"] != false {
		t.Errorf("list req = %v, res = %v", req, res)
	}
	wantObjects := []any{
		map[string]any{"key": "reports/2026 Q3/summary.txt", "size": int64(14), "etag": etag([]byte("hello, bucket\n")), "last_modified": "2026-10-10T01:02:03Z"},
		map[string]any{"key": "reports/a+b.txt", "size": int64(2), "etag": etag([]byte("ab")), "last_modified": "2026-10-10T01:02:03Z"},
	}
	if !reflect.DeepEqual(res["objects"], wantObjects) {
		t.Errorf("list res.objects = %#v, want %#v", res["objects"], wantObjects)
	}

	_, res = run(t, a, with(endpoint, map[string]any{"list": nil, "max_keys": 1}))
	if res["count"] != 1 || res["truncated"] != true {
		t.Errorf("list with max_keys res = %v", res)
	}

	ret, err := a.Run(with(endpoint, map[string]any{"delete": "reports/2026 Q3/summary.txt"}))
	if err != nil || ret["status"] != 0 || ret["res"].(map[string]any)["code"] != 204 {
		t.Errorf("delete = %v, %v", ret, err)
	}
	ret, err = a.Run(with(endpoint, map[string]any{"get": "reports/2026 Q3/summary.txt"}))
	if err != nil || ret["status"] != 1 {
		t.Errorf("get after delete = %v, %v", ret, err)
	}
}

func TestGetBody(t *testing.T) {
	s, endpoint := newStorage(t)
	a := action()

	s.put("config.json", `{"enabled": true, "limits": [1, 2]}`, "application/json")
	_, res := run(t, a, with(endpoint, map[string]any{"get": "config.json"}))
	if got, want := res["body"], map[string]any{"enabled": true, "limits": []any{float64(1), float64(2)}}; !reflect.DeepEqual(got, want) {
		t.Errorf("a JSON object: res.body = %#v, want %#v", got, want)
	}
	if res["rawbody"] != `{"enabled": true, "limits": [1, 2]}` {
		t.Errorf("a JSON object: res.rawbody = %v", res["rawbody"])
	}

	// JSON that is not said to be JSON is text.
	s.put("config.txt", `{"enabled": true}`, "text/plain")
	_, res = run(t, a, with(endpoint, map[string]any{"get": "config.txt"}))
	if res["body"] != `{"enabled": true}` || res["rawbody"] != nil {
		t.Errorf("JSON as text: res.body = %#v, res.rawbody = %#v", res["body"], res["rawbody"])
	}

	binary := string([]byte{0x89, 'P', 'N', 'G', 0xff, 0x00})
	s.put("logo.png", binary, "image/png")
	_, res = run(t, a, with(endpoint, map[string]any{"get": "logo.png"}))
	if res["body"] != "" || res["binary"] != true || res["sha256"] != hexSHA256([]byte(binary)) || res["size"] != int64(6) {
		t.Errorf("a binary object: res = %v", res)
	}

	// The cut falls inside the last character, which is left out.
	large := strings.Repeat("a", maxBody-1) + "é" + strings.Repeat("b", 100)
	s.put("large.txt", large, "text/plain")
	_, res = run(t, a, with(endpoint, map[string]any{"get": "large.txt"}))
	if res["body"] != strings.Repeat("a", maxBody-1) || res["truncated"] != true || res["binary"] != false {
		t.Errorf("a large object: body of %d bytes, truncated = %v, binary = %v", len(res["body"].(string)), res["truncated"], res["binary"])
	}
	if res["sha256"] != hexSHA256([]byte(large)) || res["size"] != int64(len(large)) {
		t.Errorf("a large object: sha256 = %v, size = %v", res["sha256"], res["size"])
	}

	s.put("empty", "", "application/octet-stream")
	_, res = run(t, a, with(endpoint, map[string]any{"get": "empty"}))
	if res["body"] != "" || res["binary"] != false || res["sha256"] != emptySHA256 || res["size"] != int64(0) {
		t.Errorf("an empty object: res = %v", res)
	}
}

func TestPut(t *testing.T) {
	s, endpoint := newStorage(t)
	a := action()

	dir := t.TempDir()
	file := filepath.Join(dir, "logo.bin")
	content := bytes.Repeat([]byte{0x00, 0xff, 0x10}, 5000)
	if err := os.WriteFile(file, content, 0o644); err != nil {
		t.Fatal(err)
	}
	req, res := run(t, a, with(endpoint, map[string]any{"put": "logo.bin", "file": file}))
	if res["code"] != 200 || req["file"] != file || req["size"] != int64(len(content)) || req["sha256"] != hexSHA256(content) {
		t.Errorf("put of a file: req = %v, res = %v", req, res)
	}
	if got := s.objects["logo.bin"]; got == nil || !bytes.Equal(got.body, content) {
		t.Errorf("put of a file stored %d bytes, want %d", len(got.body), len(content))
	}

	// Anything but a string is sent as JSON.
	run(t, a, with(endpoint, map[string]any{"put": "config.json", "body": map[string]any{"enabled": true}}))
	if got := s.objects["config.json"]; string(got.body) != `{"enabled":true}` || got.contentType != "application/json" {
		t.Errorf("put of an object stored %q as %s", got.body, got.contentType)
	}

	// An empty object is sent with its length.
	run(t, a, with(endpoint, map[string]any{"put": "empty", "body": ""}))
	last := s.got()[len(s.got())-1]
	if last.ContentLength != 0 || len(last.TransferEncoding) != 0 {
		t.Errorf("put of an empty body: Content-Length = %d, Transfer-Encoding = %v", last.ContentLength, last.TransferEncoding)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_, res = run(t, a, with(endpoint, map[string]any{"put": "empty-file", "file": empty}))
	if res["code"] != 200 || s.objects["empty-file"] == nil {
		t.Errorf("put of an empty file: res = %v", res)
	}

	for _, w := range []map[string]any{
		{"put": "x", "file": filepath.Join(dir, "none")},
		{"put": "x", "file": dir},
	} {
		if _, err := a.Run(with(endpoint, w)); err == nil || !strings.Contains(err.Error(), "with.file") {
			t.Errorf("Run(%v) error = %v, want one naming with.file", w, err)
		}
	}
}

// TestErrorIsAResult checks that what the storage refuses is a result to
// assert on, not a step that failed to run.
func TestErrorIsAResult(t *testing.T) {
	s, endpoint := newStorage(t)
	a := action()

	ret, err := a.Run(with(endpoint, map[string]any{"get": "none.txt"}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	res := ret["res"].(map[string]any)
	if ret["status"] != 1 || res["code"] != 404 || res["status"] != "404 Not Found" || res["error_code"] != "NoSuchKey" || res["error_message"] != "The specified key does not exist." {
		t.Errorf("get of a missing key = %v", ret)
	}

	// A head has no body to carry the error.
	_, res = run(t, a, with(endpoint, map[string]any{"head": "none.txt"}))
	if res["code"] != 404 || res["error_code"] != "" {
		t.Errorf("head of a missing key: res = %v", res)
	}

	_, res = run(t, a, with(endpoint, map[string]any{"list": "", "bucket": "elsewhere"}))
	if res["code"] != 404 || res["error_code"] != "NoSuchBucket" {
		t.Errorf("list of a missing bucket: res = %v", res)
	}

	s.answer = func(w http.ResponseWriter, r *http.Request) bool {
		fail(w, http.StatusForbidden, "AccessDenied", "Access Denied")
		return true
	}
	for _, w := range []map[string]any{{"get": "a"}, {"put": "a", "body": "x"}, {"delete": "a"}, {"list": ""}} {
		ret, err := a.Run(with(endpoint, w))
		if err != nil {
			t.Fatalf("Run(%v) error = %v", w, err)
		}
		if res := ret["res"].(map[string]any); ret["status"] != 1 || res["code"] != 403 || res["error_code"] != "AccessDenied" {
			t.Errorf("Run(%v) = %v", w, ret)
		}
	}
}

func TestParseRequestErrors(t *testing.T) {
	tests := []struct {
		name string
		with map[string]any
		want string
	}{
		{"unknown key", map[string]any{"get": "a", "buckt": "b"}, "not buckt"},
		{"no operation", map[string]any{"bucket": "fixtures"}, "exactly one of with.get, with.head, with.list, with.put, with.delete"},
		{"two operations", map[string]any{"get": "a", "delete": "a"}, "not get and delete together"},
		{"a list among two", map[string]any{"list": nil, "head": "a"}, "not head and list together"},
		{"no key", map[string]any{"get": ""}, "with.get must be the key of an object"},
		{"key is not a string", map[string]any{"get": 1}, "with.get must be a string"},
		{"no bucket", map[string]any{"get": "a", "bucket": nil}, "requires with.bucket"},
		{"bucket with a slash", map[string]any{"get": "a", "bucket": "evil.example/x"}, "with.bucket must be a bucket name"},
		{"bucket in capitals", map[string]any{"get": "a", "bucket": "Fixtures"}, "with.bucket must be a bucket name"},
		{"bucket with two dots", map[string]any{"get": "a", "bucket": "a..b"}, "with.bucket must be a bucket name"},
		{"region with a dot", map[string]any{"get": "a", "region": "us-east-1.example.com"}, "with.region must be the name of a region"},
		{"endpoint without a scheme", map[string]any{"get": "a", "endpoint": "localhost:9000"}, "with.endpoint must be an http or https URL"},
		{"endpoint with a query", map[string]any{"get": "a", "endpoint": "http://localhost:9000/?x=1"}, "with.endpoint must be an http or https URL"},
		{"endpoint with a user", map[string]any{"get": "a", "endpoint": "http://key:secret@localhost:9000"}, "with.endpoint must be an http or https URL"},
		{"path_style is not a boolean", map[string]any{"get": "a", "path_style": "yes"}, "with.path_style must be true or false"},
		{"one credential", map[string]any{"get": "a", "secret_access_key": nil}, "must be given together"},
		{"a token alone", map[string]any{"get": "a", "access_key_id": nil, "secret_access_key": nil, "session_token": "t"}, "must be given together"},
		{"put without a body", map[string]any{"put": "a"}, "put requires with.body or with.file"},
		{"put with both", map[string]any{"put": "a", "body": "x", "file": "x.txt"}, "with.body or with.file, not both"},
		{"body on a get", map[string]any{"get": "a", "body": "x"}, "with.body is only for put, not get"},
		{"metadata on a head", map[string]any{"head": "a", "metadata": map[string]any{"a": "b"}}, "with.metadata is only for put, not head"},
		{"metadata is not an object", map[string]any{"put": "a", "body": "x", "metadata": "a=b"}, "with.metadata must be an object"},
		{"metadata name with a space", map[string]any{"put": "a", "body": "x", "metadata": map[string]any{"a b": "c"}}, "a name a header cannot carry"},
		{"metadata value outside ASCII", map[string]any{"put": "a", "body": "x", "metadata": map[string]any{"owner": "é"}}, "with.metadata.owner must be printable ASCII"},
		{"metadata value with a line break", map[string]any{"put": "a", "body": "x", "metadata": map[string]any{"owner": "a\r\nx-amz-acl: public-read"}}, "with.metadata.owner must be printable ASCII"},
		{"max_keys on a get", map[string]any{"get": "a", "max_keys": 1}, "with.max_keys is only for list, not get"},
		{"max_keys of zero", map[string]any{"list": "", "max_keys": 0}, "with.max_keys must be a positive integer"},
		{"timeout", map[string]any{"get": "a", "timeout": "soon"}, "with.timeout"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, endpoint := newStorage(t)
			_, err := action().Run(with(endpoint, tt.with))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("Run() error = %v, want one containing %q", err, tt.want)
			}
			if n := len(s.got()); n != 0 {
				t.Errorf("%d requests were sent", n)
			}
		})
	}
}

func TestTarget(t *testing.T) {
	tests := []struct {
		name string
		with map[string]any
		want string
	}{
		{"AWS, the bucket in the host", map[string]any{"get": "a/b.txt", "bucket": "fixtures"}, "https://fixtures.s3.us-east-1.amazonaws.com/a/b.txt"},
		{"AWS, another region", map[string]any{"get": "a", "bucket": "fixtures", "region": "ap-northeast-1"}, "https://fixtures.s3.ap-northeast-1.amazonaws.com/a"},
		{"AWS in China", map[string]any{"get": "a", "bucket": "fixtures", "region": "cn-north-1"}, "https://fixtures.s3.cn-north-1.amazonaws.com.cn/a"},
		{"AWS, by path", map[string]any{"get": "a", "bucket": "fixtures", "path_style": true}, "https://s3.us-east-1.amazonaws.com/fixtures/a"},
		{"AWS, a bucket with a dot", map[string]any{"get": "a", "bucket": "assets.example.com"}, "https://s3.us-east-1.amazonaws.com/assets.example.com/a"},
		{"an endpoint, by path", map[string]any{"get": "a", "bucket": "fixtures", "endpoint": "http://localhost:9000/"}, "http://localhost:9000/fixtures/a"},
		{"an endpoint under a path", map[string]any{"get": "a", "bucket": "fixtures", "endpoint": "https://gateway.example.com/s3"}, "https://gateway.example.com/s3/fixtures/a"},
		{"an endpoint, the bucket in the host", map[string]any{"get": "a", "bucket": "fixtures", "endpoint": "https://storage.example.com", "path_style": false}, "https://fixtures.storage.example.com/a"},
		{"a key to encode", map[string]any{"get": "a b/c+d/é?x=1&y#z", "bucket": "fixtures", "path_style": true}, "https://s3.us-east-1.amazonaws.com/fixtures/a%20b/c%2Bd/%C3%A9%3Fx%3D1%26y%23z"},
		{"a key with dots and slashes", map[string]any{"get": "/a/../b//c", "bucket": "fixtures", "path_style": true}, "https://s3.us-east-1.amazonaws.com/fixtures//a/../b//c"},
		{"a list", map[string]any{"list": nil, "bucket": "fixtures"}, "https://fixtures.s3.us-east-1.amazonaws.com/?encoding-type=url&list-type=2"},
		{"a list with a prefix", map[string]any{"list": "a b/", "max_keys": 5, "bucket": "fixtures", "path_style": true}, "https://s3.us-east-1.amazonaws.com/fixtures/?encoding-type=url&list-type=2&max-keys=5&prefix=a%20b%2F"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := parseRequest(tt.with, func(string) string { return "" })
			if err != nil {
				t.Fatalf("parseRequest() error = %v", err)
			}
			if got := r.target(r.region).String(); got != tt.want {
				t.Errorf("target() = %s, want %s", got, tt.want)
			}
		})
	}
}

// TestSignMatchesAWS signs the examples of the S3 documentation, which
// gives the signature each must have.
func TestSignMatchesAWS(t *testing.T) {
	creds := credentials{accessKeyID: "AKIAIOSFODNN7EXAMPLE", secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	now := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	const scope = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, "

	req, _ := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	req.Header.Set("Range", "bytes=0-9")
	sign(req, creds, "us-east-1", emptySHA256, now)
	if got, want := req.Header.Get("Authorization"), scope+"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"; got != want {
		t.Errorf("get: Authorization = %s, want %s", got, want)
	}

	req, _ = http.NewRequest(http.MethodPut, "https://examplebucket.s3.amazonaws.com/test%24file.text", nil)
	req.Header.Set("Date", "Fri, 24 May 2013 00:00:00 GMT")
	req.Header.Set("X-Amz-Storage-Class", "REDUCED_REDUNDANCY")
	sign(req, creds, "us-east-1", hexSHA256([]byte("Welcome to Amazon S3.")), now)
	if got, want := req.Header.Get("Authorization"), scope+"SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class, Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd"; got != want {
		t.Errorf("put: Authorization = %s, want %s", got, want)
	}

	req, _ = http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/?max-keys=2&prefix=J", nil)
	sign(req, creds, "us-east-1", emptySHA256, now)
	if got, want := req.Header.Get("Authorization"), scope+"SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7"; got != want {
		t.Errorf("list: Authorization = %s, want %s", got, want)
	}
}

func TestCredentials(t *testing.T) {
	s, endpoint := newStorage(t)
	s.put("a", "x", "text/plain")
	base := map[string]any{"bucket": "fixtures", "endpoint": endpoint, "get": "a"}

	// Without any, the request is sent unsigned, as a public bucket takes it.
	ret, err := action().Run(base)
	if err != nil || ret["req"].(map[string]any)["signed"] != false {
		t.Fatalf("Run() without credentials = %v, %v", ret, err)
	}
	sent := s.got()[0]
	if sent.Header.Get("Authorization") != "" || sent.Header.Get("X-Amz-Date") != "" {
		t.Errorf("an unsigned request has %v", sent.Header)
	}

	// The environment gives them when with has none.
	env := map[string]string{"AWS_ACCESS_KEY_ID": "AKIDFROMENV", "AWS_SECRET_ACCESS_KEY": "secret", "AWS_SESSION_TOKEN": "token-from-env", "AWS_DEFAULT_REGION": "eu-west-1"}
	a := &Action{getenv: func(k string) string { return env[k] }}
	if _, err := a.Run(base); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	sent = s.got()[1]
	if auth := sent.Header.Get("Authorization"); !strings.Contains(auth, "Credential=AKIDFROMENV/") || !strings.Contains(auth, "/eu-west-1/s3/") || !strings.Contains(auth, ";x-amz-security-token,") {
		t.Errorf("Authorization = %q", auth)
	}
	if got := sent.Header.Get("X-Amz-Security-Token"); got != "token-from-env" {
		t.Errorf("X-Amz-Security-Token = %q", got)
	}

	// with wins over the environment, whole: its token is not sent along.
	w := with(endpoint, map[string]any{"get": "a", "region": "us-west-2"})
	if _, err := a.Run(w); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	sent = s.got()[2]
	if auth := sent.Header.Get("Authorization"); !strings.Contains(auth, "Credential=AKIDEXAMPLE/") || !strings.Contains(auth, "/us-west-2/s3/") || sent.Header.Get("X-Amz-Security-Token") != "" {
		t.Errorf("Authorization = %q, token = %q", auth, sent.Header.Get("X-Amz-Security-Token"))
	}

	a = &Action{getenv: func(k string) string { return map[string]string{"AWS_ACCESS_KEY_ID": "AKIDFROMENV"}[k] }}
	if _, err := a.Run(base); err == nil || !strings.Contains(err.Error(), "AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set together") {
		t.Errorf("Run() with half of the environment error = %v", err)
	}
}

// TestCredentialsAreNotShown checks that neither the log nor the result
// carries the secret access key or the session token.
func TestCredentialsAreNotShown(t *testing.T) {
	s, endpoint := newStorage(t)
	s.put("a", "x", "text/plain")

	var log bytes.Buffer
	a := &Action{
		log:    hclog.New(&hclog.LoggerOptions{Output: &log, Level: hclog.Trace}),
		getenv: func(string) string { return "" },
	}
	w := with(endpoint, map[string]any{"get": "a", "session_token": "FwoGZXIvYXdzEXAMPLETOKEN"})
	ret, err := a.Run(w)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if w["secret_access_key"] != "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY" {
		t.Errorf("with was changed: %v", w)
	}
	shown, _ := json.Marshal(ret)
	for _, secret := range []string{"wJalrXUtnFEMI", "FwoGZXIvYXdzEXAMPLETOKEN"} {
		if strings.Contains(log.String(), secret) {
			t.Errorf("the log shows %s: %s", secret, log.String())
		}
		if strings.Contains(string(shown), secret) {
			t.Errorf("the result shows %s: %s", secret, shown)
		}
	}
	if strings.Contains(string(shown), "AKIDEXAMPLE") {
		t.Errorf("the result shows the access key: %s", shown)
	}
	if !strings.Contains(log.String(), "received request parameters") {
		t.Errorf("the log has no parameters: %s", log.String())
	}
}

func TestReadOnly(t *testing.T) {
	s, endpoint := newStorage(t)
	s.put("a", "x", "text/plain")
	a := action()
	guard := actionrpc.Guard{ReadOnly: true}

	for _, w := range []map[string]any{
		{"put": "a", "body": "y"},
		// The file is not read either, so one that is not there is not what
		// stops the step.
		{"put": "a", "file": filepath.Join(t.TempDir(), "none")},
		{"delete": "a"},
	} {
		_, _, err := a.RunStep(actionrpc.Call{With: with(endpoint, w), Guard: guard})
		if !actionrpc.IsRefused(err) || !strings.Contains(err.Error(), "the run is read-only; only get, head, list are run") {
			t.Errorf("RunStep(%v) error = %v, want a refusal", w, err)
		}
	}
	if n := len(s.got()); n != 0 {
		t.Fatalf("%d requests were sent under read-only", n)
	}
	if string(s.objects["a"].body) != "x" {
		t.Errorf("the object was changed")
	}

	for _, w := range []map[string]any{{"get": "a"}, {"head": "a"}, {"list": ""}} {
		ret, _, err := a.RunStep(actionrpc.Call{With: with(endpoint, w), Guard: guard})
		if err != nil || ret["status"] != 0 {
			t.Errorf("RunStep(%v) = %v, %v", w, ret, err)
		}
	}
}

func TestAllowHost(t *testing.T) {
	s, endpoint := newStorage(t)
	s.put("a", "x", "text/plain")
	other, otherEndpoint := newStorage(t)
	other.put("a", "moved", "text/plain")
	a := action()
	host := strings.TrimPrefix(endpoint, "http://")
	otherHost := strings.TrimPrefix(otherEndpoint, "http://")

	ret, _, err := a.RunStep(actionrpc.Call{With: with(endpoint, map[string]any{"get": "a"}), Guard: actionrpc.Guard{AllowHosts: []string{host}}})
	if err != nil || ret["status"] != 0 {
		t.Fatalf("RunStep() to an allowed host = %v, %v", ret, err)
	}

	for _, w := range []map[string]any{{"get": "a"}, {"head": "a"}, {"list": ""}, {"put": "a", "body": "y"}, {"delete": "a"}} {
		_, _, err = a.RunStep(actionrpc.Call{With: with(endpoint, w), Guard: actionrpc.Guard{AllowHosts: []string{"storage.example.com"}}})
		if !actionrpc.IsRefused(err) || !strings.Contains(err.Error(), host) {
			t.Errorf("RunStep(%v) to a host not allowed error = %v, want a refusal naming %s", w, err, host)
		}
	}
	if n := len(s.got()); n != 1 {
		t.Fatalf("%d requests reached the storage, want the 1 that was allowed", n)
	}

	// The storage points to another port of the same host, which the run
	// allows or not.
	s.answer = func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Location", otherEndpoint+r.URL.RequestURI())
		w.WriteHeader(http.StatusTemporaryRedirect)
		return true
	}
	for _, w := range []map[string]any{{"get": "a"}, {"put": "a", "body": "y"}} {
		_, _, err = a.RunStep(actionrpc.Call{With: with(endpoint, w), Guard: actionrpc.Guard{AllowHosts: []string{host}}})
		if !actionrpc.IsRefused(err) || !strings.Contains(err.Error(), otherHost) {
			t.Errorf("RunStep(%v) redirected to a host not allowed error = %v, want a refusal naming %s", w, err, otherHost)
		}
	}
	if n := len(other.got()); n != 0 {
		t.Fatalf("%d requests followed the redirect to a host not allowed", n)
	}

	ret, _, err = a.RunStep(actionrpc.Call{With: with(endpoint, map[string]any{"get": "a"}), Guard: actionrpc.Guard{AllowHosts: []string{host, otherHost}}})
	if err != nil || ret["res"].(map[string]any)["body"] != "moved" {
		t.Fatalf("RunStep() redirected to an allowed host = %v, %v", ret, err)
	}
	if got := ret["req"].(map[string]any)["url"]; got != otherEndpoint+"/fixtures/a" {
		t.Errorf("req.url = %v, want where the object was read from", got)
	}
}

// TestRedirect checks that a redirected request is sent again whole, and
// signed for where it goes.
func TestRedirect(t *testing.T) {
	s, endpoint := newStorage(t)
	other, otherEndpoint := newStorage(t)
	s.answer = func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Location", otherEndpoint+r.URL.RequestURI())
		w.WriteHeader(http.StatusTemporaryRedirect)
		return true
	}
	a := action()

	_, res := run(t, a, with(endpoint, map[string]any{"put": "a.txt", "body": "sent twice"}))
	if res["code"] != 200 {
		t.Fatalf("put res = %v", res)
	}
	if got := other.objects["a.txt"]; got == nil || string(got.body) != "sent twice" {
		t.Errorf("the redirected put stored %v", got)
	}
	first, second := s.got()[0], other.got()[0]
	if first.Header.Get("Authorization") == second.Header.Get("Authorization") {
		t.Errorf("the redirected request was not signed again")
	}
	if second.Host != strings.TrimPrefix(otherEndpoint, "http://") {
		t.Errorf("the redirected request went to %s", second.Host)
	}

	// A storage that redirects without end is given up on.
	other.answer = func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Location", r.URL.RequestURI())
		w.WriteHeader(http.StatusMovedPermanently)
		return true
	}
	if _, err := a.Run(with(endpoint, map[string]any{"get": "a.txt"})); err == nil || !strings.Contains(err.Error(), "stopped after 5 redirects") {
		t.Errorf("Run() error = %v, want one about the redirects", err)
	}
}

// TestRedirectOutOfTheStorage checks that a redirect to a host that is not
// the storage's is not followed, so that nothing signed, and no session
// token, goes there.
func TestRedirectOutOfTheStorage(t *testing.T) {
	s, endpoint := newStorage(t)
	var followed int
	elsewhere := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed++ }))
	t.Cleanup(elsewhere.Close)
	// The same server by another name.
	location := strings.Replace(elsewhere.URL, "127.0.0.1", "localhost", 1)
	s.answer = func(w http.ResponseWriter, r *http.Request) bool {
		w.Header().Set("Location", location+"/fixtures/a")
		w.WriteHeader(http.StatusTemporaryRedirect)
		return true
	}

	ret, err := action().Run(with(endpoint, map[string]any{"get": "a", "session_token": "token"}))
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if res := ret["res"].(map[string]any); ret["status"] != 1 || res["code"] != 307 || res["headers"].(map[string]any)["Location"] != location+"/fixtures/a" {
		t.Errorf("Run() = %v, want the redirect as the result", ret)
	}
	if followed != 0 {
		t.Errorf("the redirect was followed")
	}
}

// roundTripper answers requests in place of a network.
type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func respond(code int, header map[string]string, body string) *http.Response {
	h := http.Header{}
	for k, v := range header {
		h.Set(k, v)
	}
	return &http.Response{StatusCode: code, Status: fmt.Sprintf("%d %s", code, http.StatusText(code)), Header: h, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body))}
}

// TestBucketOfAnotherRegion checks that on AWS a bucket that is not in the
// region asked is read from the one AWS names, when the run allows it.
func TestBucketOfAnotherRegion(t *testing.T) {
	var hosts, scopes []string
	a := &Action{
		getenv: func(string) string { return "" },
		transport: roundTripper(func(r *http.Request) (*http.Response, error) {
			hosts = append(hosts, r.URL.Host)
			_, scope, _ := strings.Cut(r.Header.Get("Authorization"), "Credential=AKIDEXAMPLE/")
			scopes = append(scopes, strings.SplitN(scope, "/", 3)[1])
			if r.URL.Host == "fixtures.s3.us-east-1.amazonaws.com" {
				return respond(http.StatusMovedPermanently, map[string]string{"X-Amz-Bucket-Region": "eu-west-1"}, `<Error><Code>PermanentRedirect</Code><Endpoint>fixtures.s3.eu-west-1.amazonaws.com</Endpoint></Error>`), nil
			}
			return respond(http.StatusOK, map[string]string{"Content-Type": "text/plain"}, "in Ireland"), nil
		}),
	}
	w := map[string]any{"bucket": "fixtures", "get": "a", "access_key_id": "AKIDEXAMPLE", "secret_access_key": "secret"}

	ret, err := a.Run(w)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if got, want := hosts, []string{"fixtures.s3.us-east-1.amazonaws.com", "fixtures.s3.eu-west-1.amazonaws.com"}; !slices.Equal(got, want) {
		t.Errorf("requests went to %v, want %v", got, want)
	}
	if got, want := scopes, []string{"us-east-1", "eu-west-1"}; !slices.Equal(got, want) {
		t.Errorf("requests were signed for %v, want %v", got, want)
	}
	req, res := ret["req"].(map[string]any), ret["res"].(map[string]any)
	if res["body"] != "in Ireland" || req["region"] != "eu-west-1" || req["url"] != "https://fixtures.s3.eu-west-1.amazonaws.com/a" {
		t.Errorf("req = %v, res = %v", req, res)
	}

	hosts = nil
	_, _, err = a.RunStep(actionrpc.Call{With: w, Guard: actionrpc.Guard{AllowHosts: []string{"fixtures.s3.us-east-1.amazonaws.com"}}})
	if !actionrpc.IsRefused(err) || !strings.Contains(err.Error(), "fixtures.s3.eu-west-1.amazonaws.com:443") {
		t.Errorf("RunStep() error = %v, want a refusal naming the host of the other region", err)
	}
	if len(hosts) != 1 {
		t.Errorf("requests went to %v, want only the host that is allowed", hosts)
	}

	// A wildcard allows the bucket in whichever region it is.
	_, _, err = a.RunStep(actionrpc.Call{With: w, Guard: actionrpc.Guard{AllowHosts: []string{"*.amazonaws.com:443"}}})
	if err != nil {
		t.Errorf("RunStep() under *.amazonaws.com error = %v", err)
	}
}

func TestTimeout(t *testing.T) {
	s, endpoint := newStorage(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	s.answer = func(http.ResponseWriter, *http.Request) bool {
		<-release
		return true
	}

	start := time.Now()
	_, err := action().Run(with(endpoint, map[string]any{"get": "a", "timeout": "50ms"}))
	if err == nil || !strings.Contains(err.Error(), "s3 get timed out after 50ms") {
		t.Errorf("Run() error = %v, want a timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("Run() took %s", elapsed)
	}
}

func TestNoAnswerIsAnError(t *testing.T) {
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	if _, err := action().Run(with(closed.URL, map[string]any{"get": "a"})); err == nil {
		t.Errorf("Run() against a closed port returned no error")
	}
}

// TestManifestsDeclare checks that action.yml, and the one the e2e workflow
// uses, declare the params and the guard the action has, so that probe
// check and the guard of a run take it as it is. probe manifest keeps what
// action.yml declares in the one of a release.
func TestManifestsDeclare(t *testing.T) {
	for _, name := range []string{"action.yml", "e2e/action/action.yml"} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		m, err := actionref.ParseManifest(data)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !slices.Equal(m.Params, params) {
			t.Errorf("%s declares params %v, want %v", name, m.Params, params)
		}
		if !slices.Equal(m.Guard, keeps) {
			t.Errorf("%s declares guard %v, want %v", name, m.Guard, keeps)
		}
	}
}
