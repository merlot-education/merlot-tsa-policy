FROM golang:1.17.8-alpine3.15 as builder

ENV GOPRIVATE=code.vereign.com

RUN apk add git

WORKDIR /go/src/code.vereign.com/gaiax/tsa/policy

ADD . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-X main.Version=$(git describe --tags --always)" -mod=vendor -o /tmp/policy ./cmd/policy/...

FROM alpine:3.15 as runner

COPY --from=builder /tmp/policy /opt/policy

WORKDIR /opt

CMD ["./policy"]
