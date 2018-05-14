package main

import (
	"log"
	"net/http"

	"github.com/auth0-community/auth0"
	"github.com/gin-gonic/gin"
)

type AuthMiddleware struct {
	Validator *auth0.JWTValidator
}

func (a *AuthMiddleware) CheckAuthentication() gin.HandlerFunc {
	return gin.HandlerFunc(func(c *gin.Context) {

		tok, err := a.Validator.ValidateRequest(c.Request)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			log.Println("Invalid token:", err)
			return
		}

		claims := map[string]interface{}{}
		err = a.Validator.Claims(c.Request, tok, &claims)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid claims"})
			c.Abort()
			log.Println("Invalid claims:", err)
			return
		}

		c.Next()
	})
}
