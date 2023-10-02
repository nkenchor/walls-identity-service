package publisher

import (
	"context"
	helper "walls-identity-service/internal/core/helper/event-helper"

	"github.com/redis/go-redis/v9"
)

type EventPublisher struct {
	redisClient *redis.Client
}

func NewPublisher(redisClient *redis.Client) *EventPublisher {
	return &EventPublisher{
		redisClient: redisClient,
	}
}

func (p *EventPublisher) PublishIdentityCreatedEvent(ctx context.Context, event interface{}) error {

	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)

}

func (p *EventPublisher) PublishPasswordCreatedEvent(ctx context.Context, event interface{}) error {

	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)

}
func (p *EventPublisher) PublishPinCreatedEvent(ctx context.Context, event interface{}) error {

	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)

}
func (p *EventPublisher) PublishIdentityEnabledEvent(ctx context.Context, event interface{}) error {

	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)

}
func (p *EventPublisher) PublishIdentityDisabledEvent(ctx context.Context, event interface{}) error {

	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)

}
func (p *EventPublisher) PublishPasswordResetEvent(ctx context.Context, event interface{}) error {
	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)
}

func (p *EventPublisher) PublishPasswordChangedEvent(ctx context.Context, event interface{}) error {
	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)
}

func (p *EventPublisher) PublishPasswordRecoveryStartedEvent(ctx context.Context, event interface{}) error {
	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)
}
func (p *EventPublisher) PublishValidateOtpRequestEvent(ctx context.Context, event interface{}) error {
	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)
}

func (p *EventPublisher) PublishPasswordRecoveryCompletedEvent(ctx context.Context, event interface{}) error {
	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)
}

func (p *EventPublisher) PublishPinResetEvent(ctx context.Context, event interface{}) error {
	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)
}

func (p *EventPublisher) PublishPinChangedEvent(ctx context.Context, event interface{}) error {
	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)
}

func (p *EventPublisher) PublishPinRecoveryStartedEvent(ctx context.Context, event interface{}) error {
	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)
}

func (p *EventPublisher) PublishPinRecoveryCompletedEvent(ctx context.Context, event interface{}) error {
	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)
}

func (p *EventPublisher) PublishLoginWithPasswordEvent(ctx context.Context, event interface{}) error {
	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)
}

func (p *EventPublisher) PublishLoginWithPinEvent(ctx context.Context, event interface{}) error {
	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)
}

func (p *EventPublisher) PublishVerifyAccessTokenEvent(ctx context.Context, event interface{}) error {
	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)
}

func (p *EventPublisher) PublishRevokeAccessTokenEvent(ctx context.Context, event interface{}) error {
	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)
}

func (p *EventPublisher) PublishLogoutEvent(ctx context.Context, event interface{}) error {
	redisHelper := helper.NewRedisClient(p.redisClient)
	return redisHelper.PublishEvent(ctx, event)
}
