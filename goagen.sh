#!/bin/bash

set -e

# preserve the value of GOFLAGS
STORED_GOFLAGS=$(go env GOFLAGS)

# force goa to not use vendored deps during generation
go env -w GOFLAGS=-mod=mod

# execute goa code generation
goa gen code.vereign.com/gaiax/tsa/policy/design

# restore the value of GOFLAGS
go env -w GOFLAGS=$STORED_GOFLAGS
