package api

import (
	"walls-identity-service/internal/adapter/extensions"
	"walls-identity-service/internal/core/domain/dto"
	errorhelper "walls-identity-service/internal/core/helper/error-helper"

	"github.com/gin-gonic/gin"
)

// @Summary Create Identity
// @Description Create Identity an User
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Success 200 {string} entity.IdentityReference "Success"
// @Failure 500 {object} helper.ErrorResponse
// @Param requestBody body dto.IdentityDTO true "User request body"
// @Router /api/identity/create [post]
func (hdl *HTTPHandler) CreateIdentity(c *gin.Context) {
	body := dto.IdentityDTO{}
	_ = c.BindJSON(&body)

	currentUser := extensions.GetCurrentUser(c)
	if !extensions.ValidateBody(c, &body) || !extensions.ValidateHeaders(c, currentUser) {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request in request body or request headers"})
		return
	}

	identity, err := hdl.identityService.CreateIdentity(c.Request.Context(), body, currentUser)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"identity_reference:": identity})
}

// @Summary Create Password
// @Description Create Password
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Param user_reference path string true "User reference"
// @Success 200 {string} entity.UserReference "Success"
// @Failure 500 {object} helper.ErrorResponse
// @Param requestBody body dto.CreatePasswordDTO true "User request body"
// @Router /api/identity/{user_reference}/create-password [post]
func (hdl *HTTPHandler) CreatePassword(c *gin.Context) {
	body := dto.CreatePasswordDTO{}
	_ = c.BindJSON(&body)
	userReference := c.Param("user_reference")

	currentUser := extensions.GetCurrentUser(c)
	if !extensions.ValidateBody(c, &body) || !extensions.ValidateHeaders(c, currentUser) {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request in request body or request headers"})
		return
	}

	identity, err := hdl.identityService.CreatePassword(c.Request.Context(), userReference, body, currentUser)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"user_reference:": identity})
}

// @Summary Create Pin
// @Description Create Pin
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Param user_reference path string true "User reference"
// @Success 200 {string} entity.UserReference "Success"
// @Failure 500 {object} helper.ErrorResponse
// @Param requestBody body dto.CreatePinDTO true "User request body"
// @Router /api/identity/{user_reference}/create-pin [post]
func (hdl *HTTPHandler) CreatePin(c *gin.Context) {
	body := dto.CreatePinDTO{}
	_ = c.BindJSON(&body)
	userReference := c.Param("user_reference")

	currentUser := extensions.GetCurrentUser(c)
	if !extensions.ValidateBody(c, &body) || !extensions.ValidateHeaders(c, currentUser) {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request in request body or request headers"})
		return
	}

	identity, err := hdl.identityService.CreatePin(c.Request.Context(), userReference, body, currentUser)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"user_reference:": identity})
}

// @Summary Enable Identity
// @Description Enable Identity
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Param user_reference path string true "User reference"
// @Success 200 {string} entity.UserReference "Success"
// @Failure 500 {object} helper.ErrorResponse
// @Router /api/identity/{user_reference}/enable [put]
func (hdl *HTTPHandler) EnableIdentity(c *gin.Context) {
	userReference := c.Param("user_reference")

	identity, err := hdl.identityService.EnableIdentity(c.Request.Context(), userReference)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"user_reference:": identity})
}

// @Summary Disable Identity
// @Description Disable Identity
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Param user_reference path string true "User reference"
// @Success 200 {string} entity.UserReference "Success"
// @Failure 500 {object} helper.ErrorResponse
// @Router /api/identity/{user_reference}/disable [put]
func (hdl *HTTPHandler) DisableIdentity(c *gin.Context) {
	userReference := c.Param("user_reference")

	identity, err := hdl.identityService.DisableIdentity(c.Request.Context(), userReference)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"user_reference:": identity})
}

// @Summary Get Identity by user reference
// @Description Get Identity by user reference
// @Tags Identity
// @Accept json
// @Produce json
// @Param user_reference path string true "User reference"
// @Success 200 {object} entity.Identity "Success"
// @Failure 500 {object} helper.ErrorResponse
// @Router /api/identity/{user_reference} [get]
func (hdl *HTTPHandler) GetIdentityByUserReference(c *gin.Context) {
	userReference := c.Param("user_reference")

	identity, err := hdl.identityService.GetIdentityByUserReference(c.Request.Context(), userReference)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, identity)
}

// @Summary Get Identity by Device
// @Description Get Identity by Device
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Success 200 {object} entity.Identity "Success"
// @Failure 500 {object} helper.ErrorResponse
// @Param requestBody body dto.DeviceDto true "User request body"
// @Router /api/identity/device [post]
func (hdl *HTTPHandler) GetIdentityByDevice(c *gin.Context) {
	body := dto.DeviceDto{}
	_ = c.BindJSON(&body)

	currentUser := extensions.GetCurrentUser(c)
	if !extensions.ValidateBody(c, &body) || !extensions.ValidateHeaders(c, currentUser) {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request in request body or request headers"})
		return
	}

	identity, err := hdl.identityService.GetIdentityByDevice(c.Request.Context(), body)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"user_reference:": identity})
}

// @Summary Reset Password
// @Description Reset User Password
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Param user_reference path string true "User reference"
// @Success 200 {string} entity.UserReference "Success"
// @Failure 500 {object} helper.ErrorResponse
// @Param requestBody body dto.ResetPasswordDTO true "User request body"
// @Router /api/password/{user_reference}/reset [put]
func (hdl *HTTPHandler) ResetPassword(c *gin.Context) {
	body := dto.ResetPasswordDTO{}
	_ = c.BindJSON(&body)
	userReference := c.Param("user_reference")

	currentUser := extensions.GetCurrentUser(c)
	if !extensions.ValidateBody(c, &body) || !extensions.ValidateHeaders(c, currentUser) {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request in request body or request headers"})
		return
	}

	identity, err := hdl.identityService.ResetPassword(c.Request.Context(), userReference, body, currentUser)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"user_reference:": identity})
}

// @Summary Change Password
// @Description Change User Password
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Param user_reference path string true "User reference"
// @Success 200 {string} entity.UserReference "Success"
// @Failure 500 {object} helper.ErrorResponse
// @Param requestBody body dto.ChangePasswordDTO true "User request body"
// @Router /api/password/{user_reference}/change [put]
func (hdl *HTTPHandler) ChangePassword(c *gin.Context) {
	body := dto.ChangePasswordDTO{}
	_ = c.BindJSON(&body)
	userReference := c.Param("user_reference")

	currentUser := extensions.GetCurrentUser(c)
	if !extensions.ValidateBody(c, &body) || !extensions.ValidateHeaders(c, currentUser) {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request in request body or request headers"})
		return
	}

	identity, err := hdl.identityService.ChangePassword(c.Request.Context(), userReference, body, currentUser)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"user_reference:": identity})
}

// @Summary Start Passsword Recovery
// @Description Start Passsword Recovery
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Param user_reference path string true "User reference"
// @Success 200 {string} entity.UserReference "OTP request has been sent. Please wait for OTP"
// @Failure 500 {object} helper.ErrorResponse
// @Router /api/password/{user_reference}/recovery/start [post]
func (hdl *HTTPHandler) StartPasswordRecovery(c *gin.Context) {
	userReference := c.Param("user_reference")
	// identityReference := c.Param("identity_reference")

	currentUser := extensions.GetCurrentUser(c)
	if !extensions.ValidateHeaders(c, currentUser) {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request in request body or request headers"})
		return
	}

	identity, err := hdl.identityService.StartPasswordRecovery(c.Request.Context(), userReference, currentUser)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"user_reference:": identity})
}

// @Summary Complete Password Recovery
// @Description Complete Password Recovery
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Param user_reference path string true "User reference"
// @Success 200 {string} entity.UserReference "Success"
// @Failure 500 {object} helper.ErrorResponse
// @Param requestBody body dto.CompletePasswordRecoveryDTO true "User request body"
// @Router /api/password/{user_reference}/recovery/complete [put]
func (hdl *HTTPHandler) CompletePasswordRecovery(c *gin.Context) {
	body := dto.CompletePasswordRecoveryDTO{}
	_ = c.BindJSON(&body)
	userReference := c.Param("user_reference")

	currentUser := extensions.GetCurrentUser(c)
	if !extensions.ValidateBody(c, &body) || !extensions.ValidateHeaders(c, currentUser) {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request in request body or request headers"})
		return
	}

	identity, err := hdl.identityService.CompletePasswordRecovery(c.Request.Context(), userReference, body, currentUser)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"user_reference:": identity})
}

// @Summary Reset Pin
// @Description Reset Pin
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Param user_reference path string true "User reference"
// @Success 200 {string} entity.UserReference "Success"
// @Failure 500 {object} helper.ErrorResponse
// @Param requestBody body dto.ResetPinDTO true "User request body"
// @Router /api/pin/{user_reference}/reset [put]
func (hdl *HTTPHandler) ResetPin(c *gin.Context) {
	body := dto.ResetPinDTO{}
	_ = c.BindJSON(&body)
	userReference := c.Param("user_reference")

	currentUser := extensions.GetCurrentUser(c)
	if !extensions.ValidateBody(c, &body) || !extensions.ValidateHeaders(c, currentUser) {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request in request body or request headers"})
		return
	}

	identity, err := hdl.identityService.ResetPin(c.Request.Context(), userReference, body, currentUser)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"user_reference:": identity})
}

// @Summary Change Pin
// @Description Change Pin
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Param user_reference path string true "User reference"
// @Success 200 {string} entity.UserReference "Success"
// @Failure 500 {object} helper.ErrorResponse
// @Param requestBody body dto.ChangePinDTO true "User request body"
// @Router /api/pin/{user_reference}/change [put]
func (hdl *HTTPHandler) ChangePin(c *gin.Context) {
	body := dto.ChangePinDTO{}
	_ = c.BindJSON(&body)
	userReference := c.Param("user_reference")

	currentUser := extensions.GetCurrentUser(c)
	if !extensions.ValidateBody(c, &body) || !extensions.ValidateHeaders(c, currentUser) {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request in request body or request headers"})
		return
	}

	identity, err := hdl.identityService.ChangePin(c.Request.Context(), userReference, body, currentUser)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"user_reference:": identity})
}

// @Summary Start Pin Recovery
// @Description Start Pin Recovery
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Param user_reference path string true "User reference"
// @Success 200 {string} entity.UserReference "OTP request has been sent. Please wait for OTP"
// @Failure 500 {object} helper.ErrorResponse
// @Router /api/pin/{user_reference}/recovery/start [post]
func (hdl *HTTPHandler) StartPinRecovery(c *gin.Context) {
	userReference := c.Param("user_reference")
	// identityReference := c.Param("identity_reference")

	currentUser := extensions.GetCurrentUser(c)
	if !extensions.ValidateHeaders(c, currentUser) {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request in request body or request headers"})
		return
	}

	identity, err := hdl.identityService.StartPinRecovery(c.Request.Context(), userReference, currentUser)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"user_reference:": identity})
}

// @Summary Complete Pin Recovery
// @Description Complete Pin Recovery
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Param user_reference path string true "User reference"
// @Success 200 {string} entity.UserReference "Success"
// @Failure 500 {object} helper.ErrorResponse
// @Param requestBody body dto.CompletePinRecoveryDTO true "User request body"
// @Router /api/pin/{user_reference}/recovery/complete [put]
func (hdl *HTTPHandler) CompletePinRecovery(c *gin.Context) {
	body := dto.CompletePinRecoveryDTO{}
	_ = c.BindJSON(&body)
	userReference := c.Param("user_reference")

	currentUser := extensions.GetCurrentUser(c)
	if !extensions.ValidateBody(c, &body) || !extensions.ValidateHeaders(c, currentUser) {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request in request body or request headers"})
		return
	}

	identity, err := hdl.identityService.CompletePinRecovery(c.Request.Context(), userReference, body, currentUser)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"user_reference:": identity})
}

// @Summary Validate OTP
// @Description Validate OTP
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Param user_reference path string true "User reference"
// @Success 200 {string} entity.UserReference "OTP sent for validation"
// @Failure 500 {object} helper.ErrorResponse
// @Param requestBody body dto.ValidateOtp true "User request body"
// @Router /api/otp/{user_reference}/validate [post]
func (hdl *HTTPHandler) ValidateOtpRequest(c *gin.Context) {
	body := dto.ValidateOtpDto{}
	_ = c.BindJSON(&body)
	userReference := c.Param("user_reference")

	currentUser := extensions.GetCurrentUser(c)
	if !extensions.ValidateBody(c, &body) || !extensions.ValidateHeaders(c, currentUser) {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request in request body or request headers"})
		return
	}

	identity, err := hdl.identityService.ValidateOtpRequest(c.Request.Context(), userReference, body, currentUser)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"user_reference:": identity})
}

// @Summary Login With Password
// @Description Login With Password
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Param user_reference path string true "User reference"
// @Success 200 {string} entity.UserReference "Success"
// @Failure 500 {object} helper.ErrorResponse
// @Param requestBody body dto.AuthenticatePasswordDTO true "User request body"
// @Router /api/login/password [post]
func (hdl *HTTPHandler) LoginWithPassword(c *gin.Context) {
	body := dto.AuthenticatePasswordDTO{}
	_ = c.BindJSON(&body)

	currentUser := extensions.GetCurrentUser(c)
	if !extensions.ValidateBody(c, &body) || !extensions.ValidateHeaders(c, currentUser) {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request in request body or request headers"})
		return
	}

	token, err := hdl.identityService.LoginWithPassword(c.Request.Context(), body, currentUser)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"token": token})
}

// @Summary Login With Pin
// @Description Login With Pin
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Param user_reference path string true "User reference"
// @Success 200 {string} entity.UserReference "Success"
// @Failure 500 {object} helper.ErrorResponse
// @Param requestBody body dto.AuthenticatePinDTO true "User request body"
// @Router /api/login/pin [post]
func (hdl *HTTPHandler) LoginWithPin(c *gin.Context) {
	body := dto.AuthenticatePinDTO{}
	_ = c.BindJSON(&body)

	currentUser := extensions.GetCurrentUser(c)
	if !extensions.ValidateBody(c, &body) || !extensions.ValidateHeaders(c, currentUser) {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request in request body or request headers"})
		return
	}

	token, err := hdl.identityService.LoginWithPin(c.Request.Context(), body, currentUser)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"token:": token})
}

// @Summary Verify Access Token
// @Description Verify Access Token
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Param user_reference path string true "User reference"
// @Success 200 {string} entity.UserReference "Success"
// @Failure 500 {object} helper.ErrorResponse
// @Param requestBody body dto.VerifyAccessTokenDTO true "User request body"
// @Router /api/token/{user_reference}/verify [post]
func (hdl *HTTPHandler) VerifyAccessToken(c *gin.Context) {
	body := dto.VerifyAccessTokenDTO{}
	_ = c.BindJSON(&body)
	userReference := c.Param("user_reference")

	currentUser := extensions.GetCurrentUser(c)
	if !extensions.ValidateBody(c, &body) || !extensions.ValidateHeaders(c, currentUser) {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request in request body or request headers"})
		return
	}

	identity, err := hdl.identityService.VerifyAccessToken(c.Request.Context(), userReference, body, currentUser)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"success:": identity})
}

// @Summary Logout
// @Description Logout User
// @Tags Identity
// @Accept json
// @Produce json

// @Param X-User-Reference header string true "User Reference"
// @Param X-Phone header string true "Phone"
// @Param X-Imei header string true "IMEI"
// @Param X-Device-Type header string true "Device Type"
// @Param X-Device-Brand header string true "Device Brand"
// @Param X-Device-Model header string true "Device Model"
// @Param X-Device-Reference header string true "Device Reference"
// @Param user_reference path string true "User reference"
// @Success 200 {string} entity.UserReference "User has been logged out"
// @Failure 500 {object} helper.ErrorResponse
// @Param requestBody body dto.RevokeAccessTokenDTO true "User request body"
// @Router /api/logout/{user_reference} [post]
func (hdl *HTTPHandler) Logout(c *gin.Context) {
	body := dto.RevokeAccessTokenDTO{}
	_ = c.BindJSON(&body)
	userReference := c.Param("user_reference")

	currentUser := extensions.GetCurrentUser(c)
	if !extensions.ValidateBody(c, &body) || !extensions.ValidateHeaders(c, currentUser) {
		c.AbortWithStatusJSON(400, gin.H{"error": "invalid request in request body or request headers"})
		return
	}

	identity, err := hdl.identityService.Logout(c.Request.Context(), userReference, body, currentUser)
	if err != nil {
		c.AbortWithStatusJSON(500, errorhelper.ErrorMessage(errorhelper.MongoDBError, err.Error()))
		return
	}

	c.JSON(201, gin.H{"user_reference:": identity})
}
