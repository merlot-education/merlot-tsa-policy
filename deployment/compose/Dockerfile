FROM golang:1.20.5

RUN go install github.com/ysmood/kit/cmd/guard@v0.25.11

ADD . /go/src/gitlab.eclipse.org/eclipse/xfsc/tsa/policy

WORKDIR /go/src/gitlab.eclipse.org/eclipse/xfsc/tsa/policy

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "/go/bin/guard -w '**/*.go' -- go run -mod=vendor ./cmd/policy/..."]
