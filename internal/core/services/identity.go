package services

import (
	"context"
	"errors"
	"fmt"

	"time"

	publisher "walls-identity-service/internal/adapter/events/publisher"
	"walls-identity-service/internal/core/domain/dto"
	"walls-identity-service/internal/core/domain/entity"
	event "walls-identity-service/internal/core/domain/event/eto"
	"walls-identity-service/internal/core/domain/mapper"
	configuration "walls-identity-service/internal/core/helper/configuration-helper"
	eto "walls-identity-service/internal/core/helper/event-helper/eto"
	logger "walls-identity-service/internal/core/helper/log-helper"
	helper "walls-identity-service/internal/core/helper/security-helper"
	ports "walls-identity-service/internal/port"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var IdentityService = &identityService{}

type identityService struct {
	identityRepository ports.IdentityRepository
	redisClient        *redis.Client
	hashManager        *helper.Argon2HashManager
	tokenManager       *helper.TokenManager
}

func NewIdentityService(identityRepository ports.IdentityRepository, redisClient *redis.Client) *identityService {
	IdentityService = &identityService{
		identityRepository: identityRepository,
		redisClient:        redisClient,
		hashManager:        helper.NewArgon2HashManager(),
		tokenManager:       helper.NewTokenManager(),
	}
	return IdentityService
}

func (service *identityService) CreateIdentity(ctx context.Context, createIdentityDto dto.IdentityDTO, currentUserDto dto.CurrentUserDto) (interface{}, error) {
	logger.LogEvent("INFO", "Creating Identity")

	identity := mapper.IdentityDtoToIdentity(createIdentityDto)

	//check if device is registered

	if !isRegisteredDevice(entity.Device(currentUserDto.Device), identity.Device) {
		logger.LogEvent("ERROR", "Unauthorized Device: This device is not registered to this user")
		return nil, errors.New("unauthorized device: this device is not registered to this user")
	}
	//check if the phone number is registered
	if !isRegisteredPhoneNumber(currentUserDto.Phone, identity.Phone) {
		logger.LogEvent("ERROR", "Unauthorized Phone: The phone number is not registered to this user")
		return nil, errors.New("unauthorized phone: the phone number is not registered to this user")
	}

	result, err := service.identityRepository.CreateIdentity(ctx, identity)
	if err != nil {
		logger.LogEvent("ERROR", "Unable to create Identity")
		return nil, errors.New("unable to create Identity")
	}

	identityCreatedEvent := event.IdentityCreatedEvent{
		Event: eto.Event{
			EventReference:     uuid.New().String(),
			EventName:          "identitycreatedevent",
			EventDate:          time.Now().Format(time.RFC3339),
			EventType:          "identitycreatedevent",
			EventSource:        configuration.ServiceConfiguration.ServiceName,
			EventUserReference: identity.IdentityReference,
			EventData:          identity,
		},
	}

	eventPublisher := publisher.NewPublisher(service.redisClient)
	eventPublisher.PublishIdentityCreatedEvent(ctx, identityCreatedEvent)

	return result, err
}

func (service *identityService) CreatePassword(ctx context.Context, user_reference string, createPasswordDto dto.CreatePasswordDTO, currentUserDto dto.CurrentUserDto) (interface{}, error) {
	logger.LogEvent("INFO", "Creating Password")

	identityData, err := service.GetIdentityByUserReference(ctx, user_reference)
	if err != nil {
		logger.LogEvent("ERROR", "Unauthorized User: Failed to fetch identity for the user with reference: "+user_reference)
		return nil, errors.New("unauthorized user: failed to retrieve identity")
	}

	identity := identityData.(entity.Identity)

	//check if device is registered

	if !isRegisteredDevice(entity.Device(currentUserDto.Device), identity.Device) {
		logger.LogEvent("ERROR", "Unauthorized Device: This device is not registered to this user")
		return nil, errors.New("unauthorized device: this device is not registered to this user")
	}
	//check if the phone number is registered
	if !isRegisteredPhoneNumber(currentUserDto.Phone, identity.Phone) {
		logger.LogEvent("ERROR", "Unauthorized Phone: The phone number is not registered to this user")
		return nil, errors.New("unauthorized phone: the phone number is not registered to this user")
	}

	passwordHash, err := service.hashManager.CreateHash(createPasswordDto.Password)
	if err != nil {
		return nil, err
	}

	identity.PasswordHash = passwordHash

	// Validate UserReference and check if the user is registered
	if currentUserDto.UserReference != identity.UserReference {
		logger.LogEvent("ERROR", "This user is not registered or does not have the rights to create the password")
		return nil, errors.New("this user is not registered or does not have the rights to create the password")
	}

	result, err := service.identityRepository.UpdateIdentity(ctx, user_reference, identity)
	if err != nil {
		logger.LogEvent("ERROR", "Unable to create Password")
		return nil, errors.New("unable to create Password")
	}

	passwordCreatedEvent := event.PasswordCreatedEvent{
		Event: eto.Event{
			EventReference:     uuid.New().String(),
			EventName:          "passwordcreatedevent",
			EventDate:          time.Now().Format(time.RFC3339),
			EventType:          "passwordcreatedevent",
			EventSource:        configuration.ServiceConfiguration.ServiceName,
			EventUserReference: identity.UserReference,
			EventData:          identity,
		},
	}

	eventPublisher := publisher.NewPublisher(service.redisClient)
	eventPublisher.PublishPasswordCreatedEvent(ctx, passwordCreatedEvent)

	return result, err
}

func (service *identityService) CreatePin(ctx context.Context, user_reference string, createPinDto dto.CreatePinDTO, currentUserDto dto.CurrentUserDto) (interface{}, error) {
	logger.LogEvent("INFO", "Creating Password")

	identityData, err := service.GetIdentityByUserReference(ctx, user_reference)
	if err != nil {
		logger.LogEvent("ERROR", "Unauthorized User: Failed to fetch identity for the user with reference: "+user_reference)
		return nil, errors.New("unauthorized user: failed to retrieve identity")
	}

	identity := identityData.(entity.Identity)

	//check if device is registered

	if !isRegisteredDevice(entity.Device(currentUserDto.Device), identity.Device) {
		logger.LogEvent("ERROR", "Unauthorized Device: This device is not registered to this user")
		return nil, errors.New("unauthorized device: this device is not registered to this user")
	}
	//check if the phone number is registered
	if !isRegisteredPhoneNumber(currentUserDto.Phone, identity.Phone) {
		logger.LogEvent("ERROR", "Unauthorized Phone: The phone number is not registered to this user")
		return nil, errors.New("unauthorized phone: the phone number is not registered to this user")
	}

	pinHash, err := service.hashManager.CreateHash(createPinDto.Pin)
	if err != nil {
		return nil, err
	}

	identity.PinHash = pinHash

	// Validate UserReference and check if the user is registered
	if currentUserDto.UserReference != identity.UserReference {
		logger.LogEvent("ERROR", "This user is not registered or does not have the rights to create the password")
		return nil, errors.New("this user is not registered or does not have the rights to create the password")
	}

	result, err := service.identityRepository.UpdateIdentity(ctx, user_reference, identity)
	if err != nil {
		logger.LogEvent("ERROR", "Unable to create Pin")
		return nil, errors.New("unable to create Pin")
	}

	pinCreatedEvent := event.PinCreatedEvent{
		Event: eto.Event{
			EventReference:     uuid.New().String(),
			EventName:          "pincreatedevent",
			EventDate:          time.Now().Format(time.RFC3339),
			EventType:          "pincreatedevent",
			EventSource:        configuration.ServiceConfiguration.ServiceName,
			EventUserReference: identity.UserReference,
			EventData:          identity,
		},
	}

	eventPublisher := publisher.NewPublisher(service.redisClient)
	eventPublisher.PublishPinCreatedEvent(ctx, pinCreatedEvent)

	return result, err
}

func (service *identityService) EnableIdentity(ctx context.Context, user_reference string) (interface{}, error) {
	logger.LogEvent("INFO", "Enable Identity")

	identityData, err := service.GetIdentityByUserReference(ctx, user_reference)
	if err != nil {
		logger.LogEvent("ERROR", "Unauthorized User: Failed to fetch identity for the user with reference: "+user_reference)
		return nil, errors.New("unauthorized user: failed to retrieve identity")
	}

	identity := identityData.(entity.Identity)

	identity.IsActive = true

	result, err := service.identityRepository.UpdateIdentity(ctx, user_reference, identity)
	if err != nil {
		logger.LogEvent("ERROR", "Unable to update identity")
		return nil, errors.New("unable to update identity")
	}

	identityEnabledEvent := event.IdentityEnabledEvent{
		Event: eto.Event{
			EventReference:     uuid.New().String(),
			EventName:          "identityenabledevent",
			EventDate:          time.Now().Format(time.RFC3339),
			EventType:          "identityenabledevent",
			EventSource:        configuration.ServiceConfiguration.ServiceName,
			EventUserReference: identity.UserReference,
			EventData:          identity,
		},
	}

	eventPublisher := publisher.NewPublisher(service.redisClient)
	eventPublisher.PublishIdentityEnabledEvent(ctx, identityEnabledEvent)

	return result, err
}

func (service *identityService) DisableIdentity(ctx context.Context, user_reference string) (interface{}, error) {
	logger.LogEvent("INFO", "Disable Identity")

	identityData, err := service.GetIdentityByUserReference(ctx, user_reference)
	if err != nil {
		logger.LogEvent("ERROR", "Unauthorized User: Failed to fetch identity for the user with reference: "+user_reference)
		return nil, errors.New("unauthorized user: failed to retrieve identity")
	}

	identity := identityData.(entity.Identity)

	identity.IsActive = false

	result, err := service.identityRepository.UpdateIdentity(ctx, user_reference, identity)
	if err != nil {
		logger.LogEvent("ERROR", "Unable to update identity")
		return nil, errors.New("unable to update identity")
	}

	identitydisabledEvent := event.IdentityDisabledEvent{
		Event: eto.Event{
			EventReference:     uuid.New().String(),
			EventName:          "identitydisabledevent",
			EventDate:          time.Now().Format(time.RFC3339),
			EventType:          "identitydisabledevent",
			EventSource:        configuration.ServiceConfiguration.ServiceName,
			EventUserReference: identity.UserReference,
			EventData:          identity,
		},
	}

	eventPublisher := publisher.NewPublisher(service.redisClient)
	eventPublisher.PublishIdentityDisabledEvent(ctx, identitydisabledEvent)

	return result, err
}

func (service *identityService) GetIdentityByUserReference(ctx context.Context, userReference string) (interface{}, error) {
	logger.LogEvent("INFO", "Fetching identity by user reference: "+userReference)
	identity, err := service.identityRepository.GetIdentityByUserReference(ctx, userReference)
	if err != nil {
		logger.LogEvent("ERROR", "Failed to fetch identity by user reference: "+userReference)
		return nil, errors.New("failed to retrieve identity")
	}

	if identity == nil {
		logger.LogEvent("ERROR", "Identity not found for reference: "+userReference)
		return nil, errors.New("identity not found")
	}

	logger.LogEvent("INFO", "Identity fetched successfully by reference: "+userReference)

	result := identity.(entity.Identity)
	return result, nil
}

func (service *identityService) ResetPassword(ctx context.Context, user_reference string, resetPasswordDto dto.ResetPasswordDTO, currentUserDto dto.CurrentUserDto) (interface{}, error) {
	logger.LogEvent("INFO", "Resetting Password")

	identityData, err := service.GetIdentityByUserReference(ctx, user_reference)
	if err != nil {
		logger.LogEvent("ERROR", "Unauthorized User: Failed to fetch identity for the user with reference: "+user_reference)
		return nil, errors.New("unauthorized user: failed to retrieve identity")
	}

	identity := identityData.(entity.Identity)
	//check if device is registered

	if !isRegisteredDevice(entity.Device(currentUserDto.Device), identity.Device) {
		logger.LogEvent("ERROR", "Unauthorized Device: This device is not registered to this user")
		return nil, errors.New("unauthorized device: this device is not registered to this user")
	}
	//check if the phone number is registered
	if !isRegisteredPhoneNumber(currentUserDto.Phone, identity.Phone) {
		logger.LogEvent("ERROR", "Unauthorized Phone: The phone number is not registered to this user")
		return nil, errors.New("unauthorized phone: the phone number is not registered to this user")
	}

	// If the token is correct, proceed with password reset
	passwordHash, err := service.hashManager.CreateHash(resetPasswordDto.NewPassword)
	if err != nil {
		return nil, err
	}

	identity.PasswordHash = passwordHash

	result, err := service.identityRepository.UpdateIdentity(ctx, user_reference, identity)
	if err != nil {
		logger.LogEvent("ERROR", "Unable to reset Password")
		return nil, errors.New("unable to reset Password")
	}

	passwordResetEvent := event.PasswordResetEvent{
		Event: eto.Event{
			EventReference:     uuid.New().String(),
			EventName:          "passwordresetevent",
			EventDate:          time.Now().Format(time.RFC3339),
			EventType:          "passwordresetevent",
			EventSource:        configuration.ServiceConfiguration.ServiceName,
			EventUserReference: identity.UserReference,
			EventData:          identity,
		},
	}

	eventPublisher := publisher.NewPublisher(service.redisClient)
	eventPublisher.PublishPasswordResetEvent(ctx, passwordResetEvent)

	return result, err
}

func (service *identityService) ChangePassword(ctx context.Context, user_reference string, changePasswordDto dto.ChangePasswordDTO, currentUserDto dto.CurrentUserDto) (interface{}, error) {
	logger.LogEvent("INFO", "Changing Password")

	// Fetch the identity by user reference
	identityData, err := service.GetIdentityByUserReference(ctx, user_reference)
	if err != nil {
		logger.LogEvent("ERROR", "Unauthorized User: Failed to fetch identity for the user with reference: "+user_reference)
		return nil, errors.New("unauthorized user: failed to retrieve identity")
	}

	// Convert identityData to entity.Identity type
	identity := identityData.(entity.Identity)

	//check if device is registered

	if !isRegisteredDevice(entity.Device(currentUserDto.Device), identity.Device) {
		logger.LogEvent("ERROR", "Unauthorized Device: This device is not registered to this user")
		return nil, errors.New("unauthorized device: this device is not registered to this user")
	}
	//check if the phone number is registered
	if !isRegisteredPhoneNumber(currentUserDto.Phone, identity.Phone) {
		logger.LogEvent("ERROR", "Unauthorized Phone: The phone number is not registered to this user")
		return nil, errors.New("unauthorized phone: the phone number is not registered to this user")
	}

	// Validate the current password by comparing with the hashed version in the database
	isPasswordMatch, err := service.hashManager.CompareHash(changePasswordDto.OldPassword, identity.PasswordHash)
	if err != nil || !isPasswordMatch {
		logger.LogEvent("ERROR", "Current password is incorrect")
		return nil, errors.New("current password is incorrect")
	}

	// Hash the new password and store it
	newPasswordHash, err := service.hashManager.CreateHash(changePasswordDto.NewPassword)
	if err != nil {
		return nil, err
	}

	identity.PasswordHash = newPasswordHash

	// Update the identity with the new password
	result, err := service.identityRepository.UpdateIdentity(ctx, user_reference, identity)
	if err != nil {
		logger.LogEvent("ERROR", "Unable to change Password")
		return nil, errors.New("unable to change Password")
	}

	// Create and publish a PasswordChangedEvent
	passwordChangedEvent := event.PasswordChangedEvent{
		Event: eto.Event{
			EventReference:     uuid.New().String(),
			EventName:          "passwordchangedevent",
			EventDate:          time.Now().Format(time.RFC3339),
			EventType:          "passwordchangedevent",
			EventSource:        configuration.ServiceConfiguration.ServiceName,
			EventUserReference: identity.UserReference,
			EventData:          identity,
		},
	}

	eventPublisher := publisher.NewPublisher(service.redisClient)
	eventPublisher.PublishPasswordChangedEvent(ctx, passwordChangedEvent)

	return result, err
}

func (service *identityService) StartPasswordRecovery(ctx context.Context, user_reference string, currentUserDto dto.CurrentUserDto) (interface{}, error) {
	logger.LogEvent("INFO", "Changing Password")

	// Fetch the identity by user reference
	identityData, err := service.GetIdentityByUserReference(ctx, user_reference)
	if err != nil {
		logger.LogEvent("ERROR", "Unauthorized User: Failed to fetch identity for the user with reference: "+user_reference)
		return nil, errors.New("unauthorized user: failed to retrieve identity")
	}

	// Convert identityData to entity.Identity type
	identity := identityData.(entity.Identity)

	//check if device is registered

	if !isRegisteredDevice(entity.Device(currentUserDto.Device), identity.Device) {
		logger.LogEvent("ERROR", "Unauthorized Device: This device is not registered to this user")
		return nil, errors.New("unauthorized device: this device is not registered to this user")
	}
	//check if the phone number is registered
	if !isRegisteredPhoneNumber(currentUserDto.Phone, identity.Phone) {
		logger.LogEvent("ERROR", "Unauthorized Phone: The phone number is not registered to this user")
		return nil, errors.New("unauthorized phone: the phone number is not registered to this user")
	}

	// Create and publish a PasswordChangedEvent
	passwordRecoveryStartedEvent := event.PasswordRecoveryStartedEvent{
		Event: eto.Event{
			EventReference:     uuid.New().String(),
			EventName:          "passwordrecoverystartedevent",
			EventDate:          time.Now().Format(time.RFC3339),
			EventType:          "passwordrecoverystartedevent",
			EventSource:        configuration.ServiceConfiguration.ServiceName,
			EventUserReference: identity.UserReference,
			EventData:          identity,
		},
	}

	eventPublisher := publisher.NewPublisher(service.redisClient)
	eventPublisher.PublishPasswordRecoveryStartedEvent(ctx, passwordRecoveryStartedEvent)

	result := "OTP request has been sent. Please wait for OTP."

	return result, err
}

func (service *identityService) ValidateOtpRequest(ctx context.Context, user_reference string, validateOtpDto dto.ValidateOtpDto, currentUserDto dto.CurrentUserDto) (interface{}, error) {

	logger.LogEvent("INFO", "Validating OTP for "+user_reference)

	// Fetch the identity by user reference
	identityData, err := service.GetIdentityByUserReference(ctx, user_reference)
	if err != nil {
		logger.LogEvent("ERROR", "Unauthorized User: Failed to fetch identity for the user with reference: "+user_reference)
		return nil, errors.New("unauthorized user: failed to retrieve identity")
	}

	// Convert identityData to entity.Identity type
	identity := identityData.(entity.Identity)

	//check if device is registered

	if !isRegisteredDevice(entity.Device(currentUserDto.Device), identity.Device) {
		logger.LogEvent("ERROR", "Unauthorized Device: This device is not registered to this user")
		return nil, errors.New("unauthorized device: this device is not registered to this user")
	}
	//check if the phone number is registered
	if !isRegisteredPhoneNumber(currentUserDto.Phone, identity.Phone) {
		logger.LogEvent("ERROR", "Unauthorized Phone: The phone number is not registered to this user")
		return nil, errors.New("unauthorized phone: the phone number is not registered to this user")
	}

	request := struct {
		UserReference string        `json:"userReference"`
		Contact       string        `json:"contact"`
		Otp           string        `json:"otp"`
		Device        dto.DeviceDto `json:"device"`
	}{
		currentUserDto.UserReference,
		validateOtpDto.Contact,
		validateOtpDto.Otp,
		validateOtpDto.Device,
	}

	validateOtpRequestEvent := event.ValidateOtpRequestEvent{
		Event: eto.Event{
			EventReference:     uuid.New().String(),
			EventName:          "validateotprequestevent",
			EventDate:          time.Now().Format(time.RFC3339),
			EventType:          "validateotprequestevent",
			EventSource:        configuration.ServiceConfiguration.ServiceName,
			EventUserReference: currentUserDto.UserReference,
			EventData:          request,
		},
	}
	eventPublisher := publisher.NewPublisher(service.redisClient)
	eventPublisher.PublishValidateOtpRequestEvent(ctx, validateOtpRequestEvent)

	result := "OTP sent for validation"

	return result, err
}
func (service *identityService) CompletePasswordRecovery(ctx context.Context, user_reference string, completePasswordDto dto.CompletePasswordRecoveryDTO, currentUser dto.CurrentUserDto) (interface{}, error) {
	logger.LogEvent("INFO", "Recovering Password")

	// Fetch the identity by user reference
	identityData, err := service.GetIdentityByUserReference(ctx, user_reference)
	if err != nil {
		logger.LogEvent("ERROR", "Unauthorized User: Failed to fetch identity for the user with reference: "+user_reference)
		return nil, errors.New("unauthorized user: failed to retrieve identity")
	}

	// Convert identityData to entity.Identity type
	identity := identityData.(entity.Identity)

	// Verify that the current user is authorized to change the password
	if currentUser.UserReference != identity.UserReference {
		logger.LogEvent("ERROR", "This user is not authorized to change the password")
		return nil, errors.New("this user is not authorized to change the password")
	}

	// Hash the new password and store it
	newPasswordHash, err := service.hashManager.CreateHash(completePasswordDto.NewPassword)
	if err != nil {
		return nil, err
	}

	identity.PasswordHash = newPasswordHash

	// Update the identity with the new password
	result, err := service.identityRepository.UpdateIdentity(ctx, user_reference, identity)
	if err != nil {
		logger.LogEvent("ERROR", "Unable to recover Password")
		return nil, errors.New("unable to recover Password")
	}

	// Create and publish a PasswordChangedEvent
	passwordRecoveryCompletedEvent := event.PasswordRecoveryCompletedEvent{
		Event: eto.Event{
			EventReference:     uuid.New().String(),
			EventName:          "passwordrecoverycompletedevent",
			EventDate:          time.Now().Format(time.RFC3339),
			EventType:          "passwordrecoverycompletedevent",
			EventSource:        configuration.ServiceConfiguration.ServiceName,
			EventUserReference: identity.UserReference,
			EventData:          identity,
		},
	}

	eventPublisher := publisher.NewPublisher(service.redisClient)
	eventPublisher.PublishPasswordRecoveryCompletedEvent(ctx, passwordRecoveryCompletedEvent)

	return result, err
}

func (service *identityService) ResetPin(ctx context.Context, user_reference string, resetPinDto dto.ResetPinDTO, currentUserDto dto.CurrentUserDto) (interface{}, error) {
	logger.LogEvent("INFO", "Resetting PIN")

	identityData, err := service.GetIdentityByUserReference(ctx, user_reference)
	if err != nil {
		logger.LogEvent("ERROR", "Unauthorized User: Failed to fetch identity for the user with reference: "+user_reference)
		return nil, errors.New("unauthorized user: failed to retrieve identity")
	}

	identity := identityData.(entity.Identity)

	if !isRegisteredDevice(entity.Device(currentUserDto.Device), identity.Device) {
		logger.LogEvent("ERROR", "Unauthorized Device: This device is not registered to this user")
		return nil, errors.New("unauthorized device: this device is not registered to this user")
	}

	if !isRegisteredPhoneNumber(currentUserDto.Phone, identity.Phone) {
		logger.LogEvent("ERROR", "Unauthorized Phone: The phone number is not registered to this user")
		return nil, errors.New("unauthorized phone: the phone number is not registered to this user")
	}

	pinHash, err := service.hashManager.CreateHash(resetPinDto.NewPin)
	if err != nil {
		return nil, err
	}

	identity.PinHash = pinHash

	result, err := service.identityRepository.UpdateIdentity(ctx, user_reference, identity)
	if err != nil {
		logger.LogEvent("ERROR", "Unable to reset PIN")
		return nil, errors.New("unable to reset PIN")
	}

	pinResetEvent := event.PinResetEvent{
		Event: eto.Event{
			EventReference:     uuid.New().String(),
			EventName:          "pinresetevent",
			EventDate:          time.Now().Format(time.RFC3339),
			EventType:          "pinresetevent",
			EventSource:        configuration.ServiceConfiguration.ServiceName,
			EventUserReference: identity.UserReference,
			EventData:          identity,
		},
	}

	eventPublisher := publisher.NewPublisher(service.redisClient)
	eventPublisher.PublishPinResetEvent(ctx, pinResetEvent)

	return result, err
}

func (service *identityService) ChangePin(ctx context.Context, user_reference string, changePinDto dto.ChangePinDTO, currentUserDto dto.CurrentUserDto) (interface{}, error) {
	logger.LogEvent("INFO", "Changing PIN")

	identityData, err := service.GetIdentityByUserReference(ctx, user_reference)
	if err != nil {
		logger.LogEvent("ERROR", "Unauthorized User: Failed to fetch identity for the user with reference: "+user_reference)
		return nil, errors.New("unauthorized user: failed to retrieve identity")
	}

	identity := identityData.(entity.Identity)

	if !isRegisteredDevice(entity.Device(currentUserDto.Device), identity.Device) {
		logger.LogEvent("ERROR", "Unauthorized Device: This device is not registered to this user")
		return nil, errors.New("unauthorized device: this device is not registered to this user")
	}

	if !isRegisteredPhoneNumber(currentUserDto.Phone, identity.Phone) {
		logger.LogEvent("ERROR", "Unauthorized Phone: The phone number is not registered to this user")
		return nil, errors.New("unauthorized phone: the phone number is not registered to this user")
	}

	isPinMatch, err := service.hashManager.CompareHash(changePinDto.OldPin, identity.PinHash)
	if err != nil || !isPinMatch {
		logger.LogEvent("ERROR", "Current PIN is incorrect")
		return nil, errors.New("current PIN is incorrect")
	}

	newPinHash, err := service.hashManager.CreateHash(changePinDto.NewPin)
	if err != nil {
		return nil, err
	}

	identity.PinHash = newPinHash

	result, err := service.identityRepository.UpdateIdentity(ctx, user_reference, identity)
	if err != nil {
		logger.LogEvent("ERROR", "Unable to change PIN")
		return nil, errors.New("unable to change PIN")
	}

	pinChangedEvent := event.PinChangedEvent{
		Event: eto.Event{
			EventReference:     uuid.New().String(),
			EventName:          "pinchangedevent",
			EventDate:          time.Now().Format(time.RFC3339),
			EventType:          "pinchangedevent",
			EventSource:        configuration.ServiceConfiguration.ServiceName,
			EventUserReference: identity.UserReference,
			EventData:          identity,
		},
	}

	eventPublisher := publisher.NewPublisher(service.redisClient)
	eventPublisher.PublishPinChangedEvent(ctx, pinChangedEvent)

	return result, err
}

func (service *identityService) StartPinRecovery(ctx context.Context, user_reference string, currentUserDto dto.CurrentUserDto) (interface{}, error) {
	logger.LogEvent("INFO", "Starting PIN Recovery")

	identityData, err := service.GetIdentityByUserReference(ctx, user_reference)
	if err != nil {
		logger.LogEvent("ERROR", "Unauthorized User: Failed to fetch identity for the user with reference: "+user_reference)
		return nil, errors.New("unauthorized user: failed to retrieve identity")
	}

	identity := identityData.(entity.Identity)

	if !isRegisteredDevice(entity.Device(currentUserDto.Device), identity.Device) {
		logger.LogEvent("ERROR", "Unauthorized Device: This device is not registered to this user")
		return nil, errors.New("unauthorized device: this device is not registered to this user")
	}

	if !isRegisteredPhoneNumber(currentUserDto.Phone, identity.Phone) {
		logger.LogEvent("ERROR", "Unauthorized Phone: The phone number is not registered to this user")
		return nil, errors.New("unauthorized phone: the phone number is not registered to this user")
	}

	pinRecoveryStartedEvent := event.PinRecoveryStartedEvent{
		Event: eto.Event{
			EventReference:     uuid.New().String(),
			EventName:          "pinrecoverystartedevent",
			EventDate:          time.Now().Format(time.RFC3339),
			EventType:          "pinrecoverystartedevent",
			EventSource:        configuration.ServiceConfiguration.ServiceName,
			EventUserReference: identity.UserReference,
			EventData:          identity,
		},
	}

	eventPublisher := publisher.NewPublisher(service.redisClient)
	eventPublisher.PublishPinRecoveryStartedEvent(ctx, pinRecoveryStartedEvent)

	result := "OTP request has been sent. Please wait for OTP."

	return result, err
}

func (service *identityService) CompletePinRecovery(ctx context.Context, user_reference string, completePinDto dto.CompletePinRecoveryDTO, currentUser dto.CurrentUserDto) (interface{}, error) {
	logger.LogEvent("INFO", "Recovering Password")

	// Fetch the identity by user reference
	identityData, err := service.GetIdentityByUserReference(ctx, user_reference)
	if err != nil {
		logger.LogEvent("ERROR", "Unauthorized User: Failed to fetch identity for the user with reference: "+user_reference)
		return nil, errors.New("unauthorized user: failed to retrieve identity")
	}

	// Convert identityData to entity.Identity type
	identity := identityData.(entity.Identity)

	// Verify that the current user is authorized to change the password
	if currentUser.UserReference != identity.UserReference {
		logger.LogEvent("ERROR", "This user is not authorized to change the password")
		return nil, errors.New("this user is not authorized to change the password")
	}

	// Hash the new password and store it
	newPinHash, err := service.hashManager.CreateHash(completePinDto.NewPin)
	if err != nil {
		return nil, err
	}

	identity.PinHash = newPinHash

	// Update the identity with the new password
	result, err := service.identityRepository.UpdateIdentity(ctx, user_reference, identity)
	if err != nil {
		logger.LogEvent("ERROR", "Unable to recover Password")
		return nil, errors.New("unable to recover Password")
	}

	// Create and publish a PasswordChangedEvent
	pinRecoveryCompletedEvent := event.PinRecoveryCompletedEvent{
		Event: eto.Event{
			EventReference:     uuid.New().String(),
			EventName:          "pinrecoverycompletedevent",
			EventDate:          time.Now().Format(time.RFC3339),
			EventType:          "pinrecoverycompletedevent",
			EventSource:        configuration.ServiceConfiguration.ServiceName,
			EventUserReference: identity.UserReference,
			EventData:          identity,
		},
	}

	eventPublisher := publisher.NewPublisher(service.redisClient)
	eventPublisher.PublishPinRecoveryCompletedEvent(ctx, pinRecoveryCompletedEvent)

	return result, err
}

func (s *identityService) GetIdentityByDevice(ctx context.Context, device dto.DeviceDto) (interface{}, error) {
	logger.LogEvent("INFO", "Fetching identity by user devicee: "+device.DeviceReference)
	// Map dto to entity here
	deviceEntity := entity.Device{
		DeviceReference: device.DeviceReference,
		Imei:            device.Imei,
		Type:            device.Type,
		Brand:           device.Brand,
		Model:           device.Model,
	}

	identity, err := s.identityRepository.GetIdentityByDevice(ctx, deviceEntity)
	if err != nil {
		logger.LogEvent("ERROR", "Failed to fetch identity by device reference: "+device.DeviceReference)
		return nil, errors.New("failed to retrieve identity")
	}

	if identity == nil {
		logger.LogEvent("ERROR", "Identity not found for device reference: "+device.DeviceReference)
		return nil, errors.New("identity not found")
	}

	logger.LogEvent("INFO", "Identity fetched successfully by device reference: "+device.DeviceReference)

	result := identity.(entity.Identity)
	return result, nil
}

func (service *identityService) LoginWithPassword(ctx context.Context, authDto dto.AuthenticatePasswordDTO, currentUserDto dto.CurrentUserDto) (interface{}, error) {
	logger.LogEvent("INFO", "Login With Password")

	identityData, err := service.GetIdentityByUserReference(ctx, authDto.UserReference)
	if err != nil {
		logger.LogEvent("ERROR", "Failed to fetch identity for the user with reference: "+authDto.UserReference)
		return nil, errors.New("failed to retrieve identity")
	}

	identity := identityData.(entity.Identity)

	if !isRegisteredDevice(entity.Device(currentUserDto.Device), identity.Device) {
		logger.LogEvent("ERROR", "Unauthorized Device: This device is not registered to this user")
		return nil, errors.New("unauthorized device: this device is not registered to this user")
	}

	if !isRegisteredPhoneNumber(currentUserDto.Phone, identity.Phone) {
		logger.LogEvent("ERROR", "Unauthorized Phone: The phone number is not registered to this user")
		return nil, errors.New("unauthorized phone: the phone number is not registered to this user")
	}

	isPasswordMatch, err := service.hashManager.CompareHash(authDto.Password, identity.PasswordHash)
	if err != nil || !isPasswordMatch {
		logger.LogEvent("ERROR", "Password is incorrect")
		return nil, errors.New("password is incorrect")
	}

	token, err := service.tokenManager.GenerateToken(
		helper.Claims{
			CurrentUserDto: currentUserDto,
		},
	)

	if err != nil {
		fmt.Println("generating token:", err)
		return nil, err
	}

	return token, nil
}

func (service *identityService) LoginWithPin(ctx context.Context, authDto dto.AuthenticatePinDTO, currentUserDto dto.CurrentUserDto) (interface{}, error) {
	logger.LogEvent("INFO", "Login With Pin")

	identityData, err := service.GetIdentityByUserReference(ctx, authDto.UserReference)
	if err != nil {
		logger.LogEvent("ERROR", "Failed to fetch identity for the user with reference: "+authDto.UserReference)
		return nil, errors.New("failed to retrieve identity")
	}

	identity := identityData.(entity.Identity)

	if !isRegisteredDevice(entity.Device(currentUserDto.Device), identity.Device) {
		logger.LogEvent("ERROR", "Unauthorized Device: This device is not registered to this user")
		return nil, errors.New("unauthorized device: this device is not registered to this user")
	}

	if !isRegisteredPhoneNumber(currentUserDto.Phone, identity.Phone) {
		logger.LogEvent("ERROR", "Unauthorized Phone: The phone number is not registered to this user")
		return nil, errors.New("unauthorized phone: the phone number is not registered to this user")
	}

	isPinMatch, err := service.hashManager.CompareHash(authDto.Pin, identity.PinHash)
	if err != nil || !isPinMatch {
		logger.LogEvent("ERROR", "PIN is incorrect")
		return nil, errors.New("PIN is incorrect")
	}

	token, err := service.tokenManager.GenerateToken(
		helper.Claims{
			CurrentUserDto: currentUserDto,
		},
	)

	if err != nil {
		return nil, err
	}

	return token, nil
}

func (service *identityService) VerifyAccessToken(ctx context.Context, user_reference string, verifyAcctionTokenDto dto.VerifyAccessTokenDTO, currentUserDto dto.CurrentUserDto) (interface{}, error) {
	logger.LogEvent("INFO", "Verifying Access Token")

	identityData, err := service.GetIdentityByUserReference(ctx, user_reference)
	if err != nil {
		logger.LogEvent("ERROR", "Failed to fetch identity for the user with reference: "+user_reference)
		return nil, errors.New("failed to retrieve identity")
	}

	identity := identityData.(entity.Identity)

	if !isRegisteredDevice(entity.Device(currentUserDto.Device), identity.Device) {
		logger.LogEvent("ERROR", "Unauthorized Device: This device is not registered to this user")
		return nil, errors.New("unauthorized device: this device is not registered to this user")
	}

	if !isRegisteredPhoneNumber(currentUserDto.Phone, identity.Phone) {
		logger.LogEvent("ERROR", "Unauthorized Phone: The phone number is not registered to this user")
		return nil, errors.New("unauthorized phone: the phone number is not registered to this user")
	}

	isTokenValid, err := service.tokenManager.VerifyToken(verifyAcctionTokenDto.AccessToken)
	if err != nil || !isTokenValid {
		logger.LogEvent("ERROR", "Access token is invalid")
		return nil, errors.New("access token is invalid")
	}

	return isTokenValid, nil
}

func (service *identityService) Logout(ctx context.Context, user_reference string, logoutDto dto.RevokeAccessTokenDTO, currentUserDto dto.CurrentUserDto) (interface{}, error) {
	logger.LogEvent("INFO", "Logout")

	identityData, err := service.GetIdentityByUserReference(ctx, user_reference)
	if err != nil {
		logger.LogEvent("ERROR", "Failed to fetch identity for the user with reference: "+user_reference)
		return nil, errors.New("failed to retrieve identity")
	}

	identity := identityData.(entity.Identity)

	if !isRegisteredDevice(entity.Device(currentUserDto.Device), identity.Device) {
		logger.LogEvent("ERROR", "Unauthorized Device: This device is not registered to this user")
		return nil, errors.New("unauthorized device: this device is not registered to this user")
	}

	if !isRegisteredPhoneNumber(currentUserDto.Phone, identity.Phone) {
		logger.LogEvent("ERROR", "Unauthorized Phone: The phone number is not registered to this user")
		return nil, errors.New("unauthorized phone: the phone number is not registered to this user")
	}

	// Invalidate the access token
	err = service.tokenManager.RevokeToken(logoutDto.AccessToken)
	if err != nil {
		return nil, errors.New("failed to revoke access token")
	}

	return "User has been logged out", nil
}

func isRegisteredDevice(currentDevice, registeredDevice entity.Device) bool {
	return currentDevice.Imei == registeredDevice.Imei &&
		currentDevice.Type == registeredDevice.Type &&
		currentDevice.Brand == registeredDevice.Brand &&
		currentDevice.Model == registeredDevice.Model &&
		currentDevice.DeviceReference == registeredDevice.DeviceReference

}

func isRegisteredPhoneNumber(currentPhone string, registeredPhone string) bool {
	return currentPhone == registeredPhone
}

func isValidExpiryMonthAndYear(month, year int) bool {
	// previous year
	if year < time.Now().Year() {
		return false
	}

	// current year previous month
	if year == time.Now().Year() && month < int(time.Now().Month()) {
		return false
	}

	// future year
	if month < 0 || month > 12 {
		return false
	}

	return true
}
