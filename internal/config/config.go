package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Server   ServerConfig
	Postgres PostgresConfig
	Redis    RedisConfig
	JWT      JWTConfig
}

type ServerConfig struct {
	Addr string
}

type PostgresConfig struct {
	Host     string
	Port     string
	User     string
	Password string
	DBName   string
}

func (p PostgresConfig) DSN() string {
	return fmt.Sprintf(
		"postgres://%s:%s@%s:%s/%s?sslmode=disable",
		p.User, p.Password, p.Host, p.Port, p.DBName,
	)
}

type RedisConfig struct {
	Addr     string
	Password string
	DB       int
}

type JWTConfig struct {
	Secret     []byte
	AccessTTL  time.Duration
	RefreshTTL time.Duration
}

func Load() (*Config, error) {
	_ = godotenv.Load()

	cfg := &Config{
		Server: ServerConfig{
			Addr: getEnv("SERVER_ADDR", ":8080"),
		},
		Postgres: PostgresConfig{
			Host:     getEnv("POSTGRES_HOST", "localhost"),
			Port:     getEnv("POSTGRES_PORT", "5432"),
			User:     getEnv("POSTGRES_USER", ""),
			Password: getEnv("POSTGRES_PASSWORD", ""),
			DBName:   getEnv("POSTGRES_DB", ""),
		},
		Redis: RedisConfig{
			Addr:     getEnv("REDIS_ADDR", "localhost:6379"),
			Password: getEnv("REDIS_PASSWORD", ""),
			DB:       getEnvInt("REDIS_DB", 0),
		},
	}

	if cfg.Postgres.User == "" {
		return nil, fmt.Errorf("POSTGRES_USER is required")
	}
	if cfg.Postgres.Password == "" {
		return nil, fmt.Errorf("POSTGRES_PASSWORD is required")
	}
	if cfg.Postgres.DBName == "" {
		return nil, fmt.Errorf("POSTGRES_DB is required")
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if len(jwtSecret) < 32 {
		return nil, fmt.Errorf("JWT_SECRET must be at least 32 characters")
	}

	cfg.JWT = JWTConfig{
		Secret:     []byte(jwtSecret),
		AccessTTL:  15 * time.Minute,
		RefreshTTL: 30 * 24 * time.Hour,
	}

	return cfg, nil
}

func getEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v, ok := os.LookupEnv(key); ok {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}
