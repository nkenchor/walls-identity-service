package ports

import (
	"context"
	"walls-identity-service/internal/core/domain/entity"
)

type IdentityRepository interface {
	CreateIdentity(ctx context.Context, identity entity.Identity) (interface{}, error)
	UpdateIdentity(ctx context.Context, identity_reference string, identity entity.Identity) (interface{}, error)
	GetIdentityByUserReference(ctx context.Context, user_reference string) (interface{}, error)
	GetIdentityByDevice(ctx context.Context, device entity.Device) (interface{}, error)
}
