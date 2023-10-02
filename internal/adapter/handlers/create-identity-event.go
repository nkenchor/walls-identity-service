package handlers

import (
	"context"
	"fmt"
	"strings"
	extraction "walls-identity-service/internal/adapter/handlers/extraction"
	"walls-identity-service/internal/core/domain/dto"
	"walls-identity-service/internal/core/domain/event/channel"
	events "walls-identity-service/internal/core/domain/event/data"
	eto "walls-identity-service/internal/core/helper/event-helper/eto"
	"walls-identity-service/internal/core/services"
)

func CreateIdentityEventHandler(ctx context.Context, event interface{}) {
	event, data, err := extraction.ExtractEventData(event, events.UserCreatedEventData{})
	if err != nil {
		fmt.Println("extracting event:", err)
		return
	}
	iEvent := event.(eto.Event)
	iEventData := data.(events.UserCreatedEventData)
	currentUserDto := dto.CurrentUserDto{
		UserReference: iEventData.UserReference,
		Phone:         iEventData.Phone,
		Device: dto.DeviceDto{
			DeviceReference: iEventData.Device.DeviceReference,
			Imei:            iEventData.Device.Imei,
			Brand:           iEventData.Device.Brand,
			Model:           iEventData.Device.Model,
			Type:            iEventData.Device.Type,
		},
	}

	// Create an instance of the IdentityService

	identity, _ := services.IdentityService.GetIdentityByUserReference(ctx, iEventData.UserReference)

	if strings.ToUpper(iEvent.EventType) == channel.AcceptedChannels[iEvent.EventType] && identity == nil {
		createIdentityDto := dto.IdentityDTO{
			Phone: iEventData.Phone,
			Device: dto.DeviceDto{
				DeviceReference: iEventData.Device.DeviceReference,
				Imei:            iEventData.Device.Imei,
				Brand:           iEventData.Device.Brand,
				Model:           iEventData.Device.Model,
				Type:            iEventData.Device.Type,
			},
		}
		// Create an instance of the UserService
		services.IdentityService.CreateIdentity(ctx, createIdentityDto, currentUserDto)
	} else {
		return

	}

}
