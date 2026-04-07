FROM golang:1.25-alpine AS builder
WORKDIR /build

COPY go.mod ./
RUN go mod download 2>/dev/null || true

COPY . .
RUN go mod tidy && CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -o /plugin ./cmd/plugin

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /plugin /plugin

ENV PLUGIN_PORT=50051
EXPOSE 50051
ENTRYPOINT ["/plugin"]
