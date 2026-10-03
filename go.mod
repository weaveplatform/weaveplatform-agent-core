module github.com/weaveplatform/weaveplatform-agent-core

go 1.27

require (
	github.com/Microsoft/go-winio v0.6.2
	github.com/deploymenttheory/go-bindings-macosplatform v0.20.1
	github.com/deploymenttheory/go-bindings-win32 v0.5.0
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	go.etcd.io/bbolt v1.5.0
	golang.org/x/sys v0.48.0
	golang.org/x/term v0.46.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/alexflint/go-arg v1.6.0 // indirect
	github.com/alexflint/go-scalar v1.2.0 // indirect
	github.com/aws/aws-sdk-go-v2 v1.43.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.14 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.19.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.31 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.31 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.32 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.24 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.31 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.32 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.106.0 // indirect
	github.com/aws/smithy-go v1.27.3 // indirect
	github.com/ebitengine/purego v0.11.1 // indirect
	github.com/golang/freetype v0.0.0-20170609003504-e2365dfdc4a0 // indirect
	github.com/google/go-github/v88 v88.0.0 // indirect
	github.com/google/go-querystring v1.2.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/narqo/go-badge v0.0.0-20230821190521-c9a75c019a59 // indirect
	github.com/rs/zerolog v1.35.1 // indirect
	github.com/vladopajic/go-test-coverage/v2 v2.19.0 // indirect
	golang.org/x/image v0.41.0 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/telemetry v0.0.0-20260908163034-4bcc4b2ee518 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/tools v0.50.0 // indirect
	golang.org/x/vuln v1.8.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260706201446-f0a921348800 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

tool (
	github.com/vladopajic/go-test-coverage/v2
	golang.org/x/vuln/cmd/govulncheck
)
