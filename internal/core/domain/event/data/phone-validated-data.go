package event

import (
	"walls-identity-service/internal/core/domain/entity"
)

type PhoneValidatedData struct {
	IdentityReference string        `json:"identity_reference"`
	UserReference     string        `json:"user_reference"`
	Otp               string        `json:"otp"`
	Phone             string        `json:"phone"`
	Device            entity.Device `json:"device"`
}
