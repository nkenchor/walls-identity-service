package event

import (
	"walls-identity-service/internal/core/helper/event-helper/eto"
)

type IdentityCreatedEvent struct {
	eto.Event
}
type PasswordCreatedEvent struct {
	eto.Event
}
type PinCreatedEvent struct {
	eto.Event
}
type IdentityValidatedEvent struct {
	eto.Event
}

type IdentityEnabledEvent struct {
	eto.Event
}

type IdentityDisabledEvent struct {
	eto.Event
}

// Events for Password Management
type PasswordResetEvent struct {
	eto.Event
}

type PasswordChangedEvent struct {
	eto.Event
}

type PasswordRecoveryStartedEvent struct {
	eto.Event
}

type ValidateOtpRequestEvent struct {
	eto.Event
}

type PasswordRecoveryCompletedEvent struct {
	eto.Event
}

// Events for PIN Management
type PinResetEvent struct {
	eto.Event
}

type PinChangedEvent struct {
	eto.Event
}

type PinRecoveryStartedEvent struct {
	eto.Event
}

type PinRecoveryCompletedEvent struct {
	eto.Event
}

// Events for Authentication and Session Management
type LoginWithPasswordEvent struct {
	eto.Event
}

type LoginWithPinEvent struct {
	eto.Event
}

type AccessTokenVerifiedEvent struct {
	eto.Event
}

type AccessTokenRevokedEvent struct {
	eto.Event
}

type UserLoggedOutEvent struct {
	eto.Event
}
