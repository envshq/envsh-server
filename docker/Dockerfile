# Stage 1: Build
FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -ldflags="-s -w" -o bin/server ./cmd/server

# Stage 2: Runtime
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /app/bin/server /usr/local/bin/envsh-server

EXPOSE 8080

ENTRYPOINT ["envsh-server"]
