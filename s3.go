package main

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/mozership/probe/actionrpc"
)

// DefaultTimeout bounds a step that does not set with.timeout.
const DefaultTimeout = 30 * time.Second

// DefaultRegion is the region a request is signed for when neither
// with.region nor the environment names one. S3-compatible storage takes it
// as a rule.
const DefaultRegion = "us-east-1"

// The operations a step can ask for, each by a key of with.
const (
	opGet    = "get"
	opHead   = "head"
	opList   = "list"
	opPut    = "put"
	opDelete = "delete"
)

// operations are the keys of with that name an operation. A step has
// exactly one of them.
var operations = []string{opGet, opHead, opList, opPut, opDelete}

// readOperations are the operations that change nothing in the bucket, and
// so the only ones run under read-only.
var readOperations = []string{opGet, opHead, opList}

// params are the keys the action takes in with. action.yml declares them,
// for probe check to report a key the action does not take.
var params = []string{
	"get", "head", "list", "put", "delete",
	"bucket", "region", "endpoint", "path_style",
	"access_key_id", "secret_access_key", "session_token",
	"body", "file", "content_type", "metadata",
	"max_keys", "timeout",
}

// keeps are the kinds of guard the action keeps to, as action.yml declares
// them: it only reads under read-only, and connects only to a host the run
// allows.
var keeps = []string{actionrpc.KindReadOnly, actionrpc.KindAllowHost}

// secretParams are the keys of with whose values are credentials, and are
// kept out of the log.
var secretParams = []string{"secret_access_key", "session_token"}

var (
	// bucketName is a name S3 takes for a bucket. It becomes part of the
	// host or of the path, so nothing else is let through.
	bucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	// regionName is the name of a region, which becomes part of the host.
	regionName = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	// headerToken is a name that can stand in a header after x-amz-meta-.
	headerToken = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+.^_|~-]+$`)
)

// Action does the operation a step describes on a bucket of S3, or of
// storage that speaks its protocol, and returns what the storage answered.
type Action struct {
	log hclog.Logger
	// transport sends the requests. It defaults to http.DefaultTransport.
	transport http.RoundTripper
	// getenv reads the environment the credentials and the region fall
	// back to. It defaults to os.Getenv.
	getenv func(string) string
	// now tells the time a request is signed at. It defaults to time.Now.
	now func() time.Time
}

// Run does the operation in with, under no guard.
func (a *Action) Run(with map[string]any) (map[string]any, error) {
	ret, _, err := a.RunStep(actionrpc.Call{With: with})
	return ret, err
}

// RunStep does the operation in call.With under the guard of the run. Once
// the storage answers, what it answered is a result, a 404 or a 403
// included; only a request that gets no answer, or a step the guard
// refuses, is an error.
func (a *Action) RunStep(call actionrpc.Call) (map[string]any, map[string]any, error) {
	if a.log == nil {
		a.log = hclog.NewNullLogger()
	}
	actionrpc.LogParams(a.log, "received request parameters", withoutSecrets(call.With))

	getenv := a.getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	req, err := parseRequest(call.With, getenv)
	if err != nil {
		return nil, nil, err
	}
	if err := checkReadOnly(call.Guard, req); err != nil {
		return nil, nil, err
	}
	ret, err := a.do(req, call.Guard)
	actionrpc.LogOutcome(a.log, "s3 "+req.op, ret, err)
	return ret, nil, err
}

// withoutSecrets returns with as it can be logged: the secret access key
// and the session token replaced, which the log would otherwise show, as
// their names are not ones Probe knows to hold a credential.
func withoutSecrets(with map[string]any) map[string]any {
	out := maps.Clone(with)
	for _, k := range secretParams {
		if _, ok := out[k]; ok {
			out[k] = "<redacted>"
		}
	}
	return out
}

// checkReadOnly returns a Refused error when the run is read-only and the
// step writes to the bucket.
func checkReadOnly(guard actionrpc.Guard, r *request) error {
	if !guard.ReadOnly || slices.Contains(readOperations, r.op) {
		return nil
	}
	return actionrpc.Refuse("%s writes to the bucket, and the run is read-only; only %s are run", r.op, strings.Join(readOperations, ", "))
}

type request struct {
	// op is the operation, and key the key it is done on, or the prefix a
	// list is narrowed to.
	op  string
	key string

	bucket string
	region string
	// endpoint is where S3-compatible storage is served, or nil for AWS.
	endpoint  *url.URL
	pathStyle bool
	creds     credentials

	// body is what a put sends, unless file names a file to send.
	body []byte
	// written is the body as with has it, for req.
	written     any
	file        string
	contentType string
	metadata    map[string]string

	// maxKeys is the most keys a list returns, or 0 for as many as the
	// storage returns by default.
	maxKeys int
	timeout time.Duration
}

func parseRequest(with map[string]any, getenv func(string) string) (*request, error) {
	r := &request{timeout: DefaultTimeout}

	for k := range with {
		if !slices.Contains(params, k) {
			return nil, fmt.Errorf("s3 action takes %s, not %s", strings.Join(params, ", "), k)
		}
	}

	var given []string
	for _, op := range operations {
		if _, ok := with[op]; ok {
			given = append(given, op)
		}
	}
	if len(given) != 1 {
		if len(given) == 0 {
			return nil, fmt.Errorf("s3 action requires exactly one of with.%s", strings.Join(operations, ", with."))
		}
		return nil, fmt.Errorf("s3 action takes exactly one of %s, not %s together", strings.Join(operations, ", "), strings.Join(given, " and "))
	}
	r.op = given[0]
	switch v := with[r.op].(type) {
	case string:
		r.key = v
	case nil:
	default:
		return nil, fmt.Errorf("with.%s must be a string, not %T", r.op, v)
	}
	if r.key == "" && r.op != opList {
		return nil, fmt.Errorf("with.%s must be the key of an object", r.op)
	}

	var err error
	if r.bucket, err = optionalString(with, "bucket"); err != nil {
		return nil, err
	}
	if r.bucket == "" {
		return nil, errors.New("s3 action requires with.bucket")
	}
	if !bucketName.MatchString(r.bucket) || strings.Contains(r.bucket, "..") {
		return nil, fmt.Errorf("with.bucket must be a bucket name of 3 to 63 lowercase letters, digits, dots and hyphens, not %q", r.bucket)
	}

	if r.region, err = optionalString(with, "region"); err != nil {
		return nil, err
	}
	if r.region == "" {
		r.region = cmp.Or(getenv("AWS_REGION"), getenv("AWS_DEFAULT_REGION"), DefaultRegion)
	}
	if !regionName.MatchString(r.region) {
		return nil, fmt.Errorf("with.region must be the name of a region, such as %s, not %q", DefaultRegion, r.region)
	}

	raw, err := optionalString(with, "endpoint")
	if err != nil {
		return nil, err
	}
	if raw != "" {
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
			return nil, fmt.Errorf("with.endpoint must be an http or https URL without a query, not %q", raw)
		}
		u.Path = strings.TrimRight(u.Path, "/")
		u.RawPath = ""
		r.endpoint = u
	}

	// A custom endpoint is addressed by path, as MinIO and the like are
	// served under one name. So is a bucket with a dot on AWS, whose name
	// the certificate of *.s3.<region>.amazonaws.com does not cover.
	r.pathStyle = r.endpoint != nil || strings.Contains(r.bucket, ".")
	if v, ok := with["path_style"]; ok && v != nil {
		b, ok := v.(bool)
		if !ok {
			return nil, fmt.Errorf("with.path_style must be true or false, not %v", v)
		}
		r.pathStyle = b
	}

	if err := r.parseCredentials(with, getenv); err != nil {
		return nil, err
	}
	if err := r.parsePut(with); err != nil {
		return nil, err
	}

	if v, ok := with["max_keys"]; ok && v != nil {
		if r.op != opList {
			return nil, fmt.Errorf("with.max_keys is only for list, not %s", r.op)
		}
		n, ok := toInt(v)
		if !ok || n < 1 {
			return nil, fmt.Errorf("with.max_keys must be a positive integer, not %v", v)
		}
		r.maxKeys = n
	}

	if v, ok := with["timeout"]; ok {
		if r.timeout, err = parseTimeout(v); err != nil {
			return nil, err
		}
	}

	return r, nil
}

// parseCredentials reads the credentials from with, or, when with has none
// of them, from the environment variables the AWS tools read. Without any,
// the requests are sent unsigned.
func (r *request) parseCredentials(with map[string]any, getenv func(string) string) error {
	var err error
	if r.creds.accessKeyID, err = optionalString(with, "access_key_id"); err != nil {
		return err
	}
	if r.creds.secretAccessKey, err = optionalString(with, "secret_access_key"); err != nil {
		return err
	}
	if r.creds.sessionToken, err = optionalString(with, "session_token"); err != nil {
		return err
	}
	if r.creds == (credentials{}) {
		r.creds = credentials{
			accessKeyID:     getenv("AWS_ACCESS_KEY_ID"),
			secretAccessKey: getenv("AWS_SECRET_ACCESS_KEY"),
			sessionToken:    getenv("AWS_SESSION_TOKEN"),
		}
		if (r.creds.accessKeyID == "") != (r.creds.secretAccessKey == "") {
			return errors.New("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set together")
		}
		if r.creds.accessKeyID == "" && r.creds.sessionToken != "" {
			return errors.New("AWS_SESSION_TOKEN needs AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY")
		}
		return nil
	}
	if r.creds.accessKeyID == "" || r.creds.secretAccessKey == "" {
		return errors.New("with.access_key_id and with.secret_access_key must be given together")
	}
	return nil
}

// parsePut reads what a put sends: with.body or with.file, and
// with.content_type and with.metadata. No other operation takes them.
func (r *request) parsePut(with map[string]any) error {
	for _, k := range []string{"body", "file", "content_type", "metadata"} {
		if v, ok := with[k]; ok && v != nil && r.op != opPut {
			return fmt.Errorf("with.%s is only for put, not %s", k, r.op)
		}
	}
	if r.op != opPut {
		return nil
	}

	var err error
	if r.file, err = optionalString(with, "file"); err != nil {
		return err
	}
	body, hasBody := with["body"]
	hasBody = hasBody && body != nil
	switch {
	case hasBody && r.file != "":
		return errors.New("put takes with.body or with.file, not both")
	case !hasBody && r.file == "":
		return errors.New("put requires with.body or with.file")
	}

	if r.contentType, err = optionalString(with, "content_type"); err != nil {
		return err
	}
	if hasBody {
		r.written = body
		if s, ok := body.(string); ok {
			r.body = []byte(s)
		} else {
			// Anything but a string is sent as JSON, as the http action
			// sends a body written as an object.
			if r.body, err = json.Marshal(body); err != nil {
				return fmt.Errorf("with.body cannot be sent as JSON: %w", err)
			}
			if r.contentType == "" {
				r.contentType = "application/json"
			}
		}
	}

	if v, ok := with["metadata"]; ok && v != nil {
		meta, ok := v.(map[string]any)
		if !ok {
			return fmt.Errorf("with.metadata must be an object, not %T", v)
		}
		r.metadata = make(map[string]string, len(meta))
		for k, v := range meta {
			if !headerToken.MatchString(k) {
				return fmt.Errorf("with.metadata has a name a header cannot carry: %q", k)
			}
			s := fmt.Sprint(v)
			if !printableASCII(s) {
				return fmt.Errorf("with.metadata.%s must be printable ASCII, which is what a header carries", k)
			}
			r.metadata[strings.ToLower(k)] = s
		}
	}
	return nil
}

// optionalString returns with[key] when it is a string, and an empty string
// when it is not given.
func optionalString(with map[string]any, key string) (string, error) {
	switch v := with[key].(type) {
	case nil:
		return "", nil
	case string:
		return v, nil
	default:
		return "", fmt.Errorf("with.%s must be a string, not %T", key, v)
	}
}

func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// toInt returns v as an int when it is a whole number.
func toInt(v any) (int, bool) {
	var f float64
	switch n := v.(type) {
	case int:
		f = float64(n)
	case int32:
		f = float64(n)
	case int64:
		f = float64(n)
	case uint64:
		f = float64(n)
	case float32:
		f = float64(n)
	case float64:
		f = n
	default:
		return 0, false
	}
	if f != math.Trunc(f) || f > math.MaxInt32 || f < math.MinInt32 {
		return 0, false
	}
	return int(f), true
}

// parseTimeout accepts a duration string such as "10s" or a number of
// seconds, as the http action does.
func parseTimeout(v any) (time.Duration, error) {
	switch t := v.(type) {
	case string:
		d, err := time.ParseDuration(t)
		if err != nil {
			return 0, fmt.Errorf("with.timeout: %w", err)
		}
		return d, nil
	case int:
		return time.Duration(t) * time.Second, nil
	case int64:
		return time.Duration(t) * time.Second, nil
	case float64:
		return time.Duration(t * float64(time.Second)), nil
	default:
		return 0, fmt.Errorf("with.timeout must be a duration or a number of seconds, not %T", v)
	}
}
