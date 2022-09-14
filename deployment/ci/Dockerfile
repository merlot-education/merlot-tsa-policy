FROM golang:1.19-alpine3.15 as builder

RUN apk add git

WORKDIR /go/src/gitlab.com/gaia-x/data-infrastructure-federation-services/tsa/policy

ADD . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-X main.Version=$(git describe --tags --always)" -mod=vendor -o /tmp/policy ./cmd/policy/...

FROM alpine:3.15 as runner

COPY --from=builder /tmp/policy /opt/policy

WORKDIR /opt

CMD ["./policy"]
