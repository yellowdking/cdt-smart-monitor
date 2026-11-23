# Multi-stage build (zero third-party Go modules -> fast, reliable offline-friendly build)
FROM golang:1.24-alpine AS builder

WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/cdt-smart-monitor ./cmd/cdt-smart-monitor

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata && adduser -D -u 10001 appuser
WORKDIR /app
COPY --from=builder /out/cdt-smart-monitor /app/cdt-smart-monitor
RUN mkdir -p /data && chown -R appuser:appuser /data

USER appuser
ENV CDT_DATA_DIR=/data \
    CDT_LISTEN=:8080 \
    TZ=Asia/Shanghai

EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["/app/cdt-smart-monitor", "-healthcheck"]
ENTRYPOINT ["/app/cdt-smart-monitor"]
