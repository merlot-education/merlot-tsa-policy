FROM golang:1.21.3-alpine3.17 as builder

RUN apk add git

WORKDIR /go/src/gitlab.eclipse.org/eclipse/xfsc/tsa/policy

ADD . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-X main.Version=$(git describe --tags --always)" -mod=vendor -o /tmp/policy ./cmd/policy/...

FROM alpine:3.17 as runner

COPY --from=builder /tmp/policy /opt/policy

WORKDIR /opt

CMD ["./policy"]
