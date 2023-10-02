package api

import (
	ports "walls-identity-service/internal/port"
)

// Httphander for the api
type HTTPHandler struct {
	identityService ports.IdentityService
}

func NewHTTPHandler(
	countryService ports.IdentityService) *HTTPHandler {
	return &HTTPHandler{
		identityService: countryService,
	}
}
