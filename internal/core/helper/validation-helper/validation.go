package helper

import (
	"regexp"
	"walls-identity-service/internal/core/domain/shared"

	"github.com/go-playground/validator/v10"
)

func ValidateValidChannel(fl validator.FieldLevel) bool {
	channel := fl.Field().Interface().(shared.Channel)

	// Check if the channel is either Phone or Email
	return channel == shared.Sms || channel == shared.Email
}

func ValidateValidContact(fl validator.FieldLevel) bool {
	contact := fl.Field().String()
	phonePattern := `^\+\d{1,3}\d{4,}$`
	match, _ := regexp.MatchString(phonePattern, contact)
	return match

}

func ValidateValidEmail(fl validator.FieldLevel) bool {
	email := fl.Field().String()
	emailPattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	match, _ := regexp.MatchString(emailPattern, email)
	return match

}

func ValidateGUID(fl validator.FieldLevel) bool {
	guid := fl.Field().String()

	// Define the regular expression pattern for a GUID-like string
	// Adjust the pattern according to the specific format you expect
	pattern := `^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`

	// Match the GUID string against the regular expression pattern
	match, _ := regexp.MatchString(pattern, guid)

	return match
}

func ValidateIMEI(fl validator.FieldLevel) bool {
	imei := fl.Field().String()

	// Define the regular expression pattern for an IMEI number
	// Adjust the pattern according to the specific format you expect
	pattern := `^\d{15}$`

	// Match the IMEI number against the regular expression pattern
	match, _ := regexp.MatchString(pattern, imei)

	return match
}
