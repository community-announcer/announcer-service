package main

import (
	"os"
	"time"

	"github.com/auth0-community/auth0"
	cors "github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	jose "gopkg.in/square/go-jose.v2"
)

func setupRouter() *gin.Engine {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"PUT", "PATCH", "DELETE", "GET", "POST"},
		AllowHeaders:     []string{"Origin", "Authorization", "Content-Type"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	secret := []byte(getEnv("API-CLIENT-SECRET", "FAKE"))
	secretProvider := auth0.NewKeyProvider(secret)
	audience := []string{getEnv("AUTH0-API-AUDIENCE", "FAKE")}

	configuration := auth0.NewConfiguration(secretProvider, audience, getEnv("AUTH0-DOMAIN", "FAKE"), jose.HS256)
	validator := auth0.NewValidator(configuration, nil)

	auth := AuthMiddleware{
		Validator: validator,
	}

	r.GET("/user/:name", auth.CheckAuthentication(), func(c *gin.Context) {
		user := c.Params.ByName("name")
		c.JSON(200, gin.H{"user": user, "status": "no value"})
	})

	return r
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

func main() {
	r := setupRouter()
	r.Run(":" + getEnv("PORT", "3000"))
}
