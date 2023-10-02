package extensions

import (

	"walls-identity-service/internal/core/domain/dto"


	"github.com/gin-gonic/gin"
)

func GetCurrentUser(c *gin.Context) dto.CurrentUserDto {

	currentUser := dto.CurrentUserDto{
		UserReference:       c.GetHeader("X-User-Reference"),
		Phone:               c.GetHeader("X-Phone"),
		Device: dto.DeviceDto{
			Imei:            c.GetHeader("X-Imei"),
			Type:            c.GetHeader("X-Device-Type"),
			Brand:           c.GetHeader("X-Device-Brand"),
			Model:           c.GetHeader("X-Device-Model"),
			DeviceReference: c.GetHeader("X-Device-Reference"),
		},
	}
	return currentUser
}
