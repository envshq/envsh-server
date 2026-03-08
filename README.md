# envsh-server

HTTP server for [envsh](https://github.com/envshq/envsh) — zero-knowledge secret sync.

The server is a **dumb blob store**. It never decrypts secrets. All encryption happens on the client.

## Quick start

```bash
make docker-up          # start Postgres 16 + Redis 7
cp .env.example .env    # configure (set JWT_SECRET)
make migrate-up         # apply schema
make run                # build + start server on :8080
```

For full setup instructions see [`DEV_GUIDE.md`](../DEV_GUIDE.md).

## Commands

```bash
make build              # compile → bin/server
make run                # build + run
make test               # run all tests
make docker-up/down     # start/stop infrastructure
make migrate-up/down    # apply/rollback migrations
make migrate-create NAME=description   # new migration pair
```

## Module

`github.com/envshq/envsh-server` — Go 1.22+
