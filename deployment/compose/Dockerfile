FROM golang:1.19.4

RUN go install github.com/canthefason/go-watcher/cmd/watcher@v0.2.4

ADD . /go/src/gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy

WORKDIR /go/src/gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy

RUN go install -mod=vendor ./cmd/policy/...

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "/go/bin/watcher -run gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy/cmd/policy -watch gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy"]
