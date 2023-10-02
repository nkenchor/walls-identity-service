package extensions

import (
	validation "walls-identity-service/internal/core/helper/validation-helper"

	"github.com/gin-gonic/gin"
)

func ValidateBody(c *gin.Context, body interface{}) bool {
	err := validation.Validate(body)
	if err != nil {
		c.AbortWithStatusJSON(400, err)
		return false
	}
	return true
}

func ValidateHeaders(c *gin.Context, currentIdentity interface{}) bool {
	err := validation.Validate(currentIdentity)
	if err != nil {
		c.AbortWithStatusJSON(400, err)
		return false
	}
	return true
}
