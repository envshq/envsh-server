# Stage 1: Build
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS builder

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w -X main.Version=$VERSION" -o bin/server ./cmd/server

# Stage 2: Runtime
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /app/bin/server /usr/local/bin/envsh-server

EXPOSE 8080

ENTRYPOINT ["envsh-server"]
