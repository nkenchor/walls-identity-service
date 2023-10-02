package entity



type Identity struct {
	IdentityReference string `json:"identity_reference" bson:"identity_reference" validate:"required,uuid4"`
	UserReference     string `json:"user_reference" bson:"user_reference" validate:"required,uuid4"`
	Phone             string `json:"phone" bson:"phone" validate:"required,valid_contact"` // Must be a valid E.164 format phone number
	PasswordHash      string `json:"password_hash" bson:"password_hash" validate:"required"`
	PinHash           string `json:"pin_hash" bson:"pin_hash" validate:"required"`
	//Salt                string `json:"salt" bson:"salt" validate:"required"`
	Device              Device `json:"device" bson:"device" validate:"required,dive"`
	IsActive            bool   `json:"is_active" bson:"is_active"`
	TwoFAEnabled        bool   `json:"2fa_enabled" bson:"2fa_enabled"`
	AccountLocked       bool   `json:"account_locked" bson:"account_locked"`
	FailedLoginAttempts int    `json:"failed_login_attempts" bson:"failed_login_attempts" validate:"min=0"`
	LastLoggedInAt      string `json:"last_logged_in_at" bson:"last_logged_in_at" validate:"omitempty,datetime=2006-01-02T15:04:05Z07:00"`
	CreatedOn           string `json:"created_on" bson:"created_on" validate:"required,datetime=2006-01-02T15:04:05Z07:00"`
	UpdatedOn           string `json:"updated_on" bson:"updated_on" validate:"required,datetime=2006-01-02T15:04:05Z07:00"`
}

type Device struct {
	DeviceReference string            `json:"device_reference" bson:"device_reference" validate:"required,uuid4"`
	Imei            string            `json:"imei" bson:"imei" validate:"required,imei"`
	Type            string`json:"type" bson:"type" validate:"required,eq=mobile|eq=tablet|eq=desktop|eq=phablet|eq=smart_watch"`
	Brand           string            `json:"brand" bson:"brand" validate:"required,alpha"`
	Model           string            `json:"model" bson:"model" validate:"required,alpha"`
}
