package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

const (
	signAlgorithm = "AWS4-HMAC-SHA256"
	signService   = "s3"
	// emptySHA256 is the digest of a request without a body.
	emptySHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// unsignedHeaders are the headers left out of a signature, as something on
// the way may change them.
var unsignedHeaders = []string{"accept-encoding", "user-agent"}

// credentials are what a request is signed with. Without an access key, a
// request is sent unsigned, as a public bucket takes it.
type credentials struct {
	accessKeyID     string
	secretAccessKey string
	sessionToken    string
}

func (c credentials) anonymous() bool {
	return c.accessKeyID == ""
}

// sign adds to req the headers of AWS Signature Version 4 for S3: the date,
// the digest of the body, the session token when there is one, and the
// Authorization built from them and from every other header of req. A
// header set on req after this is not covered by the signature.
func sign(req *http.Request, creds credentials, region, payloadHash string, now time.Time) {
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	if creds.anonymous() {
		return
	}
	date := now.UTC().Format("20060102T150405Z")
	day := date[:8]
	req.Header.Set("X-Amz-Date", date)
	if creds.sessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.sessionToken)
	}

	names := []string{"host"}
	values := map[string]string{"host": req.URL.Host}
	for name, v := range req.Header {
		name = strings.ToLower(name)
		if slices.Contains(unsignedHeaders, name) || name == "authorization" {
			continue
		}
		names = append(names, name)
		values[name] = strings.Join(v, ",")
	}
	slices.Sort(names)

	var headers strings.Builder
	for _, name := range names {
		headers.WriteString(name + ":" + strings.Join(strings.Fields(values[name]), " ") + "\n")
	}
	signedHeaders := strings.Join(names, ";")

	canonical := strings.Join([]string{
		req.Method,
		req.URL.EscapedPath(),
		canonicalQuery(req.URL.Query()),
		headers.String(),
		signedHeaders,
		payloadHash,
	}, "\n")

	scope := strings.Join([]string{day, region, signService, "aws4_request"}, "/")
	toSign := strings.Join([]string{signAlgorithm, date, scope, hexSHA256([]byte(canonical))}, "\n")

	key := hmacSHA256([]byte("AWS4"+creds.secretAccessKey), day)
	key = hmacSHA256(key, region)
	key = hmacSHA256(key, signService)
	key = hmacSHA256(key, "aws4_request")
	signature := hex.EncodeToString(hmacSHA256(key, toSign))

	req.Header.Set("Authorization", signAlgorithm+" Credential="+creds.accessKeyID+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)
}

// canonicalQuery writes a query the way a signature takes it: sorted by
// name and then by value, each percent-encoded.
func canonicalQuery(q url.Values) string {
	var pairs []string
	for name, values := range q {
		for _, v := range values {
			pairs = append(pairs, uriEncode(name, true)+"="+uriEncode(v, true))
		}
	}
	slices.Sort(pairs)
	return strings.Join(pairs, "&")
}

// uriEncode percent-encodes s as a signature expects: every byte but the
// unreserved ones, and a slash too when encodeSlash is set. A key is
// encoded with its slashes kept, as they separate the path.
func uriEncode(s string, encodeSlash bool) string {
	const upper = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_', c == '.', c == '~':
			b.WriteByte(c)
		case c == '/' && !encodeSlash:
			b.WriteByte(c)
		default:
			b.WriteByte('%')
			b.WriteByte(upper[c>>4])
			b.WriteByte(upper[c&15])
		}
	}
	return b.String()
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func hexSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
