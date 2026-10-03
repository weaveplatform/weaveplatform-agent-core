Entry points (`cmd/<binary>/main.go`). Keep them thin: parse flags with cobra
and hand off to `internal/`. `cmd/` is excluded from the coverage gate.
