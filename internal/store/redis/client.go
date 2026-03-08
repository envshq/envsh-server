package redis

import (
	"context"
	"fmt"

	"github.com/redis/go-redis/v9"
)

// Connect creates a Redis client from a URL (e.g. "redis://localhost:6379").
func Connect(ctx context.Context, redisURL string) (*redis.Client, error) {
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return nil, fmt.Errorf("parsing redis URL: %w", err)
	}
	client := redis.NewClient(opts)
	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("pinging redis: %w", err)
	}
	return client, nil
}
