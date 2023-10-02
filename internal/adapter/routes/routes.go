package routes

import (
	docs "walls-identity-service/docs"
	"walls-identity-service/internal/adapter/api"
	configuration "walls-identity-service/internal/core/helper/configuration-helper"
	errorhelper "walls-identity-service/internal/core/helper/error-helper"
	logger "walls-identity-service/internal/core/helper/log-helper"
	message "walls-identity-service/internal/core/helper/message-helper"
	"walls-identity-service/internal/core/middleware"
	services "walls-identity-service/internal/core/services"
	ports "walls-identity-service/internal/port"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func SetupRouter(identityRepository ports.IdentityRepository, redisClient *redis.Client) *gin.Engine {
	router := gin.Default()
	router.SetTrustedProxies(nil)

	identityService := services.NewIdentityService(identityRepository, redisClient)

	handler := api.NewHTTPHandler(identityService)

	logger.LogEvent("INFO", "Configuring Routes!")
	router.Use(middleware.LogRequest)

	corrs_config := cors.DefaultConfig()
	corrs_config.AllowAllOrigins = true

	router.Use(cors.New(corrs_config))
	//router.Use(middleware.SetHeaders)

	docs.SwaggerInfo.Description = "Walls Identity Service"
	docs.SwaggerInfo.Version = "1.0"
	docs.SwaggerInfo.Title = configuration.ServiceConfiguration.ServiceName

	router.POST("/api/identity/create", handler.CreateIdentity) // Create operations typically don't include identifiers in the URL
	router.POST("/api/identity/:user_reference/create-password", handler.CreatePassword)
	router.POST("/api/identity/:user_reference/create-pin", handler.CreatePin)
	router.PUT("/api/identity/:user_reference/enable", handler.EnableIdentity)
	router.PUT("/api/identity/:user_reference/disable", handler.DisableIdentity)
	router.GET("/api/identity/:user_reference", handler.GetIdentityByUserReference)
	router.POST("/api/identity/device", handler.GetIdentityByDevice) // assuming user_reference is relevant here
	router.PUT("/api/password/:user_reference/reset", handler.ResetPassword)
	router.PUT("/api/password/:user_reference/change", handler.ChangePassword)
	router.POST("/api/password/:user_reference/recovery/start", handler.StartPasswordRecovery)
	router.PUT("/api/password/:user_reference/recovery/complete", handler.CompletePasswordRecovery)
	router.PUT("/api/pin/:user_reference/reset", handler.ResetPin)
	router.PUT("/api/pin/:user_reference/change", handler.ChangePin)
	router.POST("/api/pin/:user_reference/recovery/start", handler.StartPinRecovery)
	router.PUT("/api/pin/:user_reference/recovery/complete", handler.CompletePinRecovery)
	router.POST("/api/otp/:user_reference/validate", handler.ValidateOtpRequest)
	router.POST("/api/login/password", handler.LoginWithPassword) // Login operations typically don't include identifiers in the URL
	router.POST("/api/login/pin", handler.LoginWithPin)           // Login operations typically don't include identifiers in the URL
	router.POST("/api/token/:user_reference/verify", handler.VerifyAccessToken)
	router.POST("/api/logout/:user_reference", handler.Logout)

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	router.NoRoute(func(ctx *gin.Context) {
		ctx.JSON(404,
			errorhelper.ErrorMessage(errorhelper.NoResourceError, message.NoResourceFound))
	})

	return router
}
