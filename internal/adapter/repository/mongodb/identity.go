package repository

import (
	"context"
	"fmt"
	"time"
	"walls-identity-service/internal/core/domain/entity"
	logger "walls-identity-service/internal/core/helper/log-helper"
	ports "walls-identity-service/internal/port"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type IdentityInfra struct {
	Collection *mongo.Collection
}

func NewIdentity(Collection *mongo.Collection) *IdentityInfra {
	return &IdentityInfra{Collection}
}

// IdentityRepo implements the repository.IdentityRepository interface
var _ ports.IdentityRepository = &IdentityInfra{}

func (r *IdentityInfra) CreateIdentity(ctx context.Context, identity entity.Identity) (interface{}, error) {
	logger.LogEvent("INFO", "Persisting identity with reference: "+identity.IdentityReference)

	_, err := r.Collection.InsertOne(ctx, identity)
	if err != nil {
		return nil, err
	}

	logger.LogEvent("INFO", "Persisting identity with reference: "+identity.IdentityReference+" completed successfully...")
	return identity.IdentityReference, nil
}

func (r *IdentityInfra) GetIdentityByReference(ctx context.Context, identity_reference string) (interface{}, error) {
	identity := entity.Identity{}
	filter := bson.M{"reference": identity_reference}

	err := r.Collection.FindOne(ctx, filter).Decode(&identity)

	if err != nil {
		fmt.Println("Error db:", err)
		return nil, err
	}

	logger.LogEvent("INFO", "Retrieving identity with identity reference: "+identity_reference+" completed successfully. ")

	return identity, nil
}

func (r *IdentityInfra) GetIdentityByUserReference(ctx context.Context, user_reference string) (interface{}, error) {
	filter := bson.M{"user_reference": user_reference}

	identity := entity.Identity{}
	err := r.Collection.FindOne(ctx, filter).Decode(&identity)
	if err != nil {
		return nil, err
	}

	logger.LogEvent("INFO", "Retrieving identity with user reference: "+user_reference+" completed successfully. ")
	return identity, nil
}

func (r *IdentityInfra) GetIdentityByDevice(ctx context.Context, device entity.Device) (interface{}, error) {
	filter := bson.M{"device.type": device.Type, "device.imei": device.Imei, "device.brand": device.Brand, "device.model": device.Model}

	identity := entity.Identity{}
	err := r.Collection.FindOne(ctx, filter).Decode(&identity)
	if err != nil {
		return nil, err
	}
	logger.LogEvent("INFO", "Retrieving identity with device reference: "+device.DeviceReference+" completed successfully. ")
	return identity, nil
}

func (r *IdentityInfra) UpdateIdentity(ctx context.Context, user_reference string, identity entity.Identity) (interface{}, error) {
	logger.LogEvent("INFO", "Updating identity with reference: "+user_reference)

	filter := bson.M{"user_reference": user_reference}
	update := bson.M{
		"$set": bson.M{
			"user_reference":        identity.UserReference,
			"password_hash":         identity.PasswordHash,
			"pin_hash":              identity.PinHash,
			"device":                identity.Device,
			"is_active":             identity.IsActive,
			"2fa_enabled":           identity.TwoFAEnabled,
			"account_locked":        identity.AccountLocked,
			"failed_login_attempts": identity.FailedLoginAttempts,
			"last_logged_in_at":     identity.LastLoggedInAt,
			"created_on":            identity.CreatedOn,
			"updated_on":            time.Now().Format(time.RFC3339),
		},
	}

	_, err := r.Collection.UpdateOne(ctx, filter, update)
	if err != nil {
		return nil, err
	}

	logger.LogEvent("INFO", "Identity with reference "+user_reference+" updated successfully")
	return user_reference, nil
}
