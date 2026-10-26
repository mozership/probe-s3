// Command probe-s3 serves a Probe action that reads and writes objects in S3
// and S3-compatible storage. Probe starts it for a step that uses
// github.com/mozership/probe-s3@<commit>.
package main

import (
	"github.com/hashicorp/go-hclog"
	"github.com/mozership/probe/actionrpc"
)

// version is set at build time.
var version = "dev"

func main() {
	actionrpc.Serve(func(log hclog.Logger) actionrpc.Action {
		return &Action{log: log}
	})
}
