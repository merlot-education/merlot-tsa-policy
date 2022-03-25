FROM golang:1.17.8

ENV GO111MODULE=on
ENV GOPRIVATE=code.vereign.com

RUN go install github.com/canthefason/go-watcher/cmd/watcher@v0.2.4

ADD . /go/src/code.vereign.com/gaiax/tsa/policy

WORKDIR /go/src/code.vereign.com/gaiax/tsa/policy

RUN go install -mod=vendor ./cmd/policy/...

EXPOSE 8080

ENTRYPOINT ["sh", "-c", "/go/bin/watcher -run code.vereign.com/gaiax/tsa/policy/cmd/policy -watch code.vereign.com/gaiax/tsa/policy"]
