FROM golang:1.22-alpine AS builder
WORKDIR /app

COPY go.mod ./
RUN go mod download || true

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /gitshield ./cmd/gitshield

FROM alpine:3.20
RUN apk add --no-cache git ca-certificates
COPY --from=builder /gitshield /usr/local/bin/gitshield

WORKDIR /workspace
ENTRYPOINT ["gitshield"]
CMD ["scan"]