# envsh-server

The server for [envsh](https://github.com/envshq/envsh) — zero-knowledge secret management.

The server is a **dumb blob store**. It receives ciphertext and stores it. All encryption and decryption happens on the client. A compromised server leaks nothing usable.

## Quick start

```bash
git clone https://github.com/envshq/envsh-server
cd envsh-server
make docker-up          # start Postgres 16 + Redis 7
cp .env.example .env    # configure (set JWT_SECRET)
make migrate-up         # apply schema
make run                # start server on :8080
```

## Docker image

Pre-built multi-arch images (amd64 + arm64):

```bash
docker pull ghcr.io/envshq/envsh-server:latest
```

See the [self-hosting guide](https://envsh.dev/guides/self-hosting/) for Docker Compose setup with Postgres, Redis, and migrations.

## Commands

```bash
make build              # compile → bin/server
make run                # build + run
make test               # run all tests
make lint               # golangci-lint
make docker-up/down     # start/stop infrastructure
make migrate-up/down    # apply/rollback migrations
```

## Links

- [Documentation](https://envsh.dev)
- [CLI repo](https://github.com/envshq/envsh)

## License

AGPL-3.0
