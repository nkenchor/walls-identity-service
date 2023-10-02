package mapper

import (
	"time"
	"walls-identity-service/internal/core/domain/dto"
	"walls-identity-service/internal/core/domain/entity"

	"github.com/google/uuid"
)

func IdentityDtoToIdentity(identityDto dto.IdentityDTO) entity.Identity {

	identity := entity.Identity{
		// IdentityReference: identityDto.UserReference,
		IdentityReference: uuid.New().String(),
		UserReference:     identityDto.UserReference,
		CreatedOn:         time.Now().Format(time.RFC3339),
		UpdatedOn:         time.Now().Format(time.RFC3339),
		Phone:             identityDto.Phone,
		Device:            DeviceDtoToDevice(identityDto.Device),
	}
	return identity
}

func DeviceDtoToDevice(deviceDto dto.DeviceDto) entity.Device {
	device := entity.Device{
		DeviceReference: deviceDto.DeviceReference,
		Imei:            deviceDto.Imei,
		Type:            deviceDto.Type,
		Brand:           deviceDto.Brand,
		Model:           deviceDto.Model,
	}
	return device
}
