# syntax=docker/dockerfile:1.6
FROM golang:1.25 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download
COPY . .
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -o /server ./cmd/kyc-onboarding && \
    CGO_ENABLED=0 GOOS=linux go build -o /migrate ./cmd/migrate

FROM alpine:3.20
RUN apk add --no-cache wget && \
    addgroup -S app && adduser -S app -G app
COPY --from=builder /server /server
COPY --from=builder /migrate /migrate
EXPOSE 8080
USER app
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -qO- http://localhost:8080/healthz || exit 1
ENTRYPOINT ["/server"]