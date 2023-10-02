package helper

import (
	"reflect"
	errorhelper "walls-identity-service/internal/core/helper/error-helper"
	logger "walls-identity-service/internal/core/helper/log-helper"

	"github.com/go-playground/validator/v10"
)

var (
	validate *validator.Validate
)

func init() {
	validate = validator.New()
	validate.RegisterValidation("valid_channel", ValidateValidChannel)
	validate.RegisterValidation("valid_contact", ValidateValidContact)
	validate.RegisterValidation("valid_email", ValidateValidEmail)
	validate.RegisterValidation("guid", ValidateGUID)
	validate.RegisterValidation("imei", ValidateIMEI)
}

func Validate(data interface{}) error {
	logger.LogEvent("INFO", "Validating "+reflect.TypeOf(data).String()+" Data...")
	err := validate.Struct(data)
	if err != nil {
		var fieldErrors []validator.FieldError
		logger.LogEvent("ERROR", "Error validating struct: "+err.Error())

		for _, errs := range err.(validator.ValidationErrors) {
			fieldErrors = append(fieldErrors, errs)
		}
		return errorhelper.ErrorArrayToError(fieldErrors)
	}
	logger.LogEvent("INFO", reflect.TypeOf(data).String()+" Data Validated Successfully...")
	return nil
}
