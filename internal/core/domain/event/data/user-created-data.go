package event

import (
	"walls-identity-service/internal/core/domain/entity"
)

type UserCreatedEventData struct {
	UserReference string        `json:"user_reference"`
	Phone         string        `json:"phone"`
	Device        entity.Device `json:"device"`
}
