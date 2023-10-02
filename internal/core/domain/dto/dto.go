package dto



type IdentityDTO struct {
	UserReference string    `json:"user_reference" bson:"user_reference" validate:"required,uuid4"` // Must be a valid UUID v4 string
	Phone         string    `json:"phone" bson:"phone" validate:"required,valid_contact"`           // Must be a valid E.164 format phone number
	Device        DeviceDto `json:"device" bson:"device" validate:"required"`
}

type CreatePasswordDTO struct {
	Password string `json:"password" bson:"password" validate:"required,len=8,alphanum"` // Must be alphanumeric and length between 8 and 30
}

type CreatePinDTO struct {
	Pin string `json:"pin" bson:"pin" validate:"required,len=6,number"` // Must be numeric and exactly 4 characters long
}

type ChangePasswordDTO struct {
	OldPassword string `json:"old_password" bson:"old_password" validate:"required,len=8,alphanum"` // Must be alphanumeric and length between 8 and 30
	NewPassword string `json:"new_password" bson:"new_password" validate:"required,len=8,alphanum"` // Must be alphanumeric and length between 8 and 30
}

type ChangePinDTO struct {
	OldPin string `json:"old_pin" bson:"old_pin" validate:"required,len=6,number"` // Must be numeric and exactly 4 characters long
	NewPin string `json:"new_pin" bson:"new_pin" validate:"required,len=6,number"` // Must be numeric and exactly 4 characters long
}

type AuthenticatePasswordDTO struct {
	UserReference string `json:"user_reference" bson:"user_reference" validate:"required,uuid4"` // Must be a valid UUID v4 string
	Password      string `json:"password" bson:"password" validate:"required,len=8,alphanum"`    // Must be alphanumeric and length between 8 and 30
}

type AuthenticatePinDTO struct {
	UserReference string `json:"user_reference" bson:"user_reference" validate:"required,uuid4"` // Must be a valid UUID v4 string
	Pin           string `json:"pin" bson:"pin" validate:"required,len=6,number"`                // Must be numeric and exactly 6 characters long
}

type CompleteRecoveryDTO struct {
	RecoveryToken string `json:"recovery_token" bson:"recovery_token" validate:"required,uuid4"`          // Must be a valid UUID v4 string
	NewCredential string `json:"new_credential" bson:"new_credential" validate:"required,len=8,alphanum"` // For password, must be alphanumeric and length between 8 and 30. For pin, must be numeric and exactly 4 characters long
}

type UpdateDeviceDTO struct {
	Device DeviceDto `json:"device" bson:"device" validate:"required,dive"` // Dive into nested struct for validation
}

type RevokeAccessTokenDTO struct {
	AccessToken string `json:"access_token" bson:"access_token" validate:"required"` // Access token should not be empty
}

type StartRecoveryDTO struct {
	IdentityReference string `json:"identity_reference" bson:"identity_reference" validate:"required,uuid4"` // Must be a valid UUID v4 string
}

type ConfirmRecoveryDTO struct {
	RecoveryToken string `json:"recovery_token" bson:"recovery_token" validate:"required,uuid4"` // Must be a valid UUID v4 string
}

type EnableDisableIdentityDTO struct {
	IdentityReference string `json:"identity_reference" bson:"identity_reference" validate:"required,uuid4"` // Must be a valid UUID v4 string
}

type ResetPasswordDTO struct {
	NewPassword string `json:"new_password" bson:"new_password" validate:"required,len=8,alphanum"` // Must be alphanumeric and length between 8 and 30
}

type CompletePasswordRecoveryDTO struct {
	NewPassword string `json:"new_password" bson:"new_password" validate:"required,len=8,alphanum"` // Must be alphanumeric and length between 8 and 30
}

type ResetPinDTO struct {
	NewPin string `json:"new_pin" bson:"new_pin" validate:"required,len=6,number"` // Must be numeric and exactly 4 characters long
}

type CompletePinRecoveryDTO struct {
	OTP    string `json:"otp" bson:"otp" validate:"required,len=6,number"`         // Must be numeric and exactly 6 digits long
	NewPin string `json:"new_pin" bson:"new_pin" validate:"required,len=6,number"` // Must be numeric and exactly 4 characters long
}

type VerifyAccessTokenDTO struct {
	AccessToken string `json:"access_token" bson:"access_token" validate:"required"` // Access token should not be empty
}

type DeviceDto struct {
	DeviceReference string            `json:"device_reference" bson:"device_reference"`
	Imei            string            `json:"imei" bson:"imei" validate:"required,imei"`
	Type            string`json:"type" bson:"type" validate:"required,eq=mobile|eq=tablet|eq=desktop|eq=phablet|eq=smart_watch"`
	Brand           string            `json:"brand" bson:"brand" validate:"required,alpha"`
	Model           string            `json:"model" bson:"model" validate:"required,alpha"`
}

type CurrentUserDto struct {
	UserReference string    `json:"user_reference" bson:"user_reference" validate:"required,guid,min=32,max=38"`
	Phone         string    `json:"phone" bson:"phone" validate:"required,valid_contact"`
	Device        DeviceDto `json:"device" bson:"device" validate:"required,dive"`
}


type ValidateOtpDto struct {
	Otp     string    `json:"otp" bson:"otp" validate:"required,len=6"`
	Contact string    `json:"contact" bson:"contact" validate:"valid_contact"`
	Device  DeviceDto `json:"device" bson:"device" validate:"required,dive"`
}
