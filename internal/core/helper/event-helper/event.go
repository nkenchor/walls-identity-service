package helper

import (
	"context"
	"encoding/json"
	"log"
	"reflect"
	"strings"
	logger "walls-identity-service/internal/core/helper/log-helper"

	"github.com/redis/go-redis/v9"
)

type RedisClient struct {
	client *redis.Client
}

func NewRedisClient(client *redis.Client) *RedisClient {
	return &RedisClient{
		client: client,
	}
}

func (r *RedisClient) SubscribeToEvent(ctx context.Context, event interface{}, eventHandler func(context.Context, interface{})) error {
	// Get the channel name from the event object's type

	pubSub := r.client.PSubscribe(ctx, event.(string))
	defer pubSub.Close()

	ch := pubSub.Channel()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg := <-ch:
			var eventData interface{}

			err := json.Unmarshal([]byte(msg.Payload), &eventData)
			if err != nil {
				log.Printf("Error decoding event: %v\n", err)
				logger.LogEvent("ERROR", "Error decoding event: "+err.Error())
				continue
			}

			eventHandler(ctx, eventData) // Pass the appropriate IdentityRepository instance here
		}
	}

}

func (r *RedisClient) PublishEvent(ctx context.Context, event interface{}) error {
	eventBytes, err := json.Marshal(event)
	if err != nil {
		return err
	}

	// Get the channel name from the event object's type
	eventChannel := strings.ToUpper(reflect.TypeOf(event).Name())

	err = r.client.Publish(ctx, eventChannel, string(eventBytes)).Err()
	if err != nil {
		return err
	}

	return nil
}
