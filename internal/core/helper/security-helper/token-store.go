package helper

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

type TokenBlacklist struct {
	client *redis.Client
}

func NewTokenBlacklist(client *redis.Client) *TokenBlacklist {
	return &TokenBlacklist{client: client}
}

// RevokeToken adds the token to the store with an expiry duration.
func (store *TokenBlacklist) RevokeToken(token string, expiry time.Duration) error {
	ctx := context.Background()
	err := store.client.Set(ctx, token, "revoked", expiry).Err()
	return err
}

// IsTokenRevoked checks if a token is in the store, i.e., has been revoked.
func (store *TokenBlacklist) IsTokenRevoked(token string) (bool, error) {
	ctx := context.Background()
	_, err := store.client.Get(ctx, token).Result()

	if err == redis.Nil {
		// If the token is not in the store, it's not revoked.
		return false, nil
	} else if err != nil {
		// If there was an error, return it.
		return false, err
	}

	// If there was no error and the token is in the store, it's revoked.
	return true, nil
}
