package main

import (
	"encoding/json"
	"net/http"
	"errors"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/auth0/go-jwt-middleware"
)

type Response struct {
	Message string `json:"message"`
}

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N string `json:"n"`
	E string `json:"e"`
	X5c []string `json:"x5c"`
}

func setupRouter() *gin.Engine {
	r := gin.Default()

	//r.Use(cors.New(cors.Config{
	//	AllowOrigins:     []string{"*"},
	//	AllowMethods:     []string{"PUT", "PATCH", "DELETE", "GET", "POST"},
	//	AllowHeaders:     []string{"Origin", "Authorization", "Content-Type"},
	//	ExposeHeaders:    []string{"Content-Length"},
	//	AllowCredentials: true,
	//	MaxAge:           12 * time.Hour,
	//}))
	//
	//secret := []byte(getEnv("API-CLIENT-SECRET", "FAKE-API-CLIENT-SECRET"))
	//secretProvider := auth0.NewKeyProvider(secret)
	//audience := []string{getEnv("AUTH0-API-AUDIENCE", "FAKE-API-AUDIENCE")}
	//
	//configuration := auth0.NewConfiguration(secretProvider, audience, getEnv("AUTH0-DOMAIN", "FAKE-DOMAIN"), jose.HS256)
	//validator := auth0.NewValidator(configuration, nil)
	//
	//auth := AuthMiddleware{
	//	Validator: validator,
	//}

	r.GET("/api/public", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "public api"})
	})

	r.GET("/api/private", checkJWT(), func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "private api"})
	})

	return r
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

var jwtMiddleware = jwtmiddleware.New(jwtmiddleware.Options {
	ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
		// Verify 'aud' claim
		aud := "https://community-announcer.eu.auth0.com/api/v2/"
		checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
		if !checkAud {
			return token, errors.New("Invalid audience.")
		}
		// Verify 'iss' claim
		iss := "https://community-announcer.eu.auth0.com/"
		checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
		if !checkIss {
			return token, errors.New("Invalid issuer.")
		}

		cert, err := getPemCert(token)
		if err != nil {
			panic(err.Error())
		}

		result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
		return result, nil
	},
	SigningMethod: jwt.SigningMethodRS256,
})

func main() {
	r := setupRouter()

	r.Run(":" + getEnv("PORT", "3000"))
}

func checkJWT() gin.HandlerFunc {
	return func(c *gin.Context) {
		jwtMid := *jwtMiddleware
		if err := jwtMid.CheckJWT(c.Writer, c.Request); err != nil {
			c.AbortWithStatus(401)
		}
	}
}

func getPemCert(token *jwt.Token) (string, error) {
	cert := ""
	resp, err := http.Get("https://community-announcer.eu.auth0.com/.well-known/jwks.json")

	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	for k, _ := range jwks.Keys {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + jwks.Keys[k].X5c[0] + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		err := errors.New("Unable to find appropriate key.")
		return cert, err
	}

	return cert, nil
}
