FROM golang:1.20.5

RUN go install github.com/ysmood/kit/cmd/guard@v0.25.11

ADD . /go/src/gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy

WORKDIR /go/src/gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "/go/bin/guard -w '**/*.go' -- go run -mod=vendor ./cmd/policy/..."]
