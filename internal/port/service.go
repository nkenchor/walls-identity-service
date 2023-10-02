package ports

import (
	"context"
	"walls-identity-service/internal/core/domain/dto"
)

type IdentityService interface {
	// Identity Creation and Management
	CreateIdentity(ctx context.Context, dto dto.IdentityDTO, currentUser dto.CurrentUserDto) (interface{}, error)
	CreatePassword(ctx context.Context, user_reference string, dto dto.CreatePasswordDTO, currentUser dto.CurrentUserDto) (interface{}, error)
	CreatePin(ctx context.Context, user_reference string, dto dto.CreatePinDTO, currentUser dto.CurrentUserDto) (interface{}, error)
	EnableIdentity(ctx context.Context, user_reference string) (interface{}, error)
	DisableIdentity(ctx context.Context, user_reference string) (interface{}, error)
	GetIdentityByUserReference(ctx context.Context, user_reference string) (interface{}, error)
	GetIdentityByDevice(ctx context.Context, device dto.DeviceDto) (interface{}, error)

	// Password Management
	ResetPassword(ctx context.Context, user_reference string, dto dto.ResetPasswordDTO, currentUser dto.CurrentUserDto) (interface{}, error)
	ChangePassword(ctx context.Context, user_reference string, dto dto.ChangePasswordDTO, currentUser dto.CurrentUserDto) (interface{}, error)
	StartPasswordRecovery(ctx context.Context, user_reference string, currentUserDto dto.CurrentUserDto) (interface{}, error)
	CompletePasswordRecovery(ctx context.Context, user_reference string, dto dto.CompletePasswordRecoveryDTO, currentUser dto.CurrentUserDto) (interface{}, error)

	// PIN Management
	ResetPin(ctx context.Context, user_reference string, dto dto.ResetPinDTO, currentUser dto.CurrentUserDto) (interface{}, error)
	ChangePin(ctx context.Context, user_reference string, dto dto.ChangePinDTO, currentUser dto.CurrentUserDto) (interface{}, error)
	StartPinRecovery(ctx context.Context, user_reference string, currentUserDto dto.CurrentUserDto) (interface{}, error)
	CompletePinRecovery(ctx context.Context, user_reference string, dto dto.CompletePinRecoveryDTO, currentUser dto.CurrentUserDto) (interface{}, error)

	// Otp
	ValidateOtpRequest(ctx context.Context, user_reference string, validateOtpDto dto.ValidateOtpDto, currentUserDto dto.CurrentUserDto) (interface{}, error)

	// Authentication and Session Management
	LoginWithPassword(ctx context.Context, dto dto.AuthenticatePasswordDTO, currentUser dto.CurrentUserDto) (interface{}, error)
	LoginWithPin(ctx context.Context, dto dto.AuthenticatePinDTO, currentUser dto.CurrentUserDto) (interface{}, error)
	VerifyAccessToken(ctx context.Context, user_reference string, dto dto.VerifyAccessTokenDTO, currentUser dto.CurrentUserDto) (interface{}, error)
	Logout(ctx context.Context, user_reference string, dto dto.RevokeAccessTokenDTO, currentUser dto.CurrentUserDto) (interface{}, error)
}
