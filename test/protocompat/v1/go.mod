// Protocol-1 fixture: a module built from the module SDK tags that speak
// protocol 1, pinned so it always builds the same protocol-1 module. Keep this
// directory for as long as core's window includes protocol 1; a new protocol
// adds a vN/ directory beside it.
//
// The requirements below are the protocol-1 SDK's own module paths. Do not
// rewrite, tidy or bump them; the module proxy keeps the tags resolvable.
module github.com/deploymenttheory/weave-protocompat-v1

go 1.26.5

require github.com/deploymenttheory/weaveplatform-sdk v0.2.1

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/deploymenttheory/weaveplatform-api v0.2.0 // indirect
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
