package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds all environment-variable-based configuration for the server.
type Config struct {
	DatabaseURL   string
	RedisURL      string
	JWTSecret     string
	ServerAddr    string
	LogLevel      string
	LogFormat     string
	EmailProvider string
	EmailFrom     string
	ResendAPIKey    string
	FreeTierSeatMax int
}

// Load reads configuration from environment variables and validates required fields.
func Load() (*Config, error) {
	cfg := &Config{
		DatabaseURL:   os.Getenv("DATABASE_URL"),
		RedisURL:      os.Getenv("REDIS_URL"),
		JWTSecret:     os.Getenv("JWT_SECRET"),
		ServerAddr:    getEnvDefault("SERVER_ADDR", ":8080"),
		LogLevel:      getEnvDefault("LOG_LEVEL", "info"),
		LogFormat:     getEnvDefault("LOG_FORMAT", "json"),
		EmailProvider: getEnvDefault("EMAIL_PROVIDER", "console"),
		EmailFrom:     getEnvDefault("EMAIL_FROM", "noreply@envsh.dev"),
		ResendAPIKey:    os.Getenv("RESEND_API_KEY"),
		FreeTierSeatMax: getEnvDefaultInt("FREE_TIER_SEAT_MAX", 0),
	}
	if cfg.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if cfg.RedisURL == "" {
		return nil, fmt.Errorf("REDIS_URL is required")
	}
	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}
	return cfg, nil
}

func getEnvDefault(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getEnvDefaultInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
