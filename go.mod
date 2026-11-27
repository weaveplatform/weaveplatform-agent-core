module github.com/weaveplatform/weaveplatform-agent-core

go 1.27

require (
	github.com/Microsoft/go-winio v0.6.4
	github.com/deploymenttheory/go-bindings-macosplatform v0.20.1
	github.com/deploymenttheory/go-bindings-win32 v0.7.0
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.3
	go.etcd.io/bbolt v1.5.0
	golang.org/x/sys v0.50.0
	golang.org/x/term v0.48.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
)

require (
	github.com/alexflint/go-arg v1.6.1 // indirect
	github.com/alexflint/go-scalar v1.2.0 // indirect
	github.com/aws/aws-sdk-go-v2 v1.48.1 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.28 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.21.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.13 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.13 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.26 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.11.14 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.20.13 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.116.1 // indirect
	github.com/aws/smithy-go v1.28.11 // indirect
	github.com/ebitengine/purego v0.11.3 // indirect
	github.com/golang/freetype v0.0.0-20170609003504-e2365dfdc4a0 // indirect
	github.com/google/go-github/v88 v88.0.0 // indirect
	github.com/google/go-querystring v1.2.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-colorable v0.1.16 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/narqo/go-badge v0.0.0-20230821190521-c9a75c019a59 // indirect
	github.com/rs/zerolog v1.35.1 // indirect
	github.com/vladopajic/go-test-coverage/v2 v2.23.0 // indirect
	golang.org/x/image v0.48.0 // indirect
	golang.org/x/mod v0.43.0 // indirect
	golang.org/x/net v0.63.0 // indirect
	golang.org/x/sync v0.25.0 // indirect
	golang.org/x/telemetry v0.0.0-20261124234621-1402bdb29cb5 // indirect
	golang.org/x/text v0.44.0 // indirect
	golang.org/x/tools v0.53.0 // indirect
	golang.org/x/vuln v1.10.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20261123191846-1e707ab9fbc2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

tool (
	github.com/vladopajic/go-test-coverage/v2
	golang.org/x/vuln/cmd/govulncheck
)
