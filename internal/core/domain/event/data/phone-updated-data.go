package event

import (
	"walls-identity-service/internal/core/domain/entity"
)

type PhoneUpdatedData struct {
	IdentityReference string        `json:"identity_reference"`
	UserReference     string        `json:"user_reference"`
	Phone             string        `json:"phone"`
	Device            entity.Device `json:"device"`
}
