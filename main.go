package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"

	"github.com/auth0/go-jwt-middleware"
	"github.com/community-announcer/announcer-service/persistance"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
)

var (
	dp *persistance.PostgreSqlDraftProvider
)

type Response struct {
	Message string `json:"message"`
}

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

func corsMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "https://www.community-announcer.com")
		c.Writer.Header().Set("Access-Control-Max-Age", "86400")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE, UPDATE")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Origin, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")
		c.Writer.Header().Set("Access-Control-Expose-Headers", "Content-Length")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(200)
		} else {
			c.Next()
		}
	}
}

func setupRouter() *gin.Engine {
	r := gin.Default()

	r.Use(gin.Recovery())
	r.Use(corsMiddleware())

	r.GET("/.well-known/live", func(c *gin.Context) {
		c.Status(http.StatusNoContent)
	})

	r.GET("/api/public", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "public api"})
	})

	r.GET("/api/private", checkJWT(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "private api"})
	})

	r.GET("/api/drafts", checkJWT(), func(c *gin.Context) {
		if drafts, err := dp.All(); err != nil {
			c.JSON(http.StatusInternalServerError, err)
		} else {
			c.JSON(http.StatusOK, drafts)
		}
	})

	return r
}

func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}

var jwtMiddleware = jwtmiddleware.New(jwtmiddleware.Options{
	ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
		aud := getEnv("AUTH0-API-IDENTIFIER", "a1b2c3d4")
		checkAud := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
		if !checkAud {
			return token, fmt.Errorf("Invalid audience. Expected: %s Current: %s", aud, token.Claims.(jwt.MapClaims)["aud"].(string))
		}

		iss := getEnv("AUTH0-DOMAIN", "http://localhost/")
		checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
		if !checkIss {
			return token, fmt.Errorf("Invalid issuer. Expected: %s Current: %s", iss, token.Claims.(jwt.MapClaims)["iss"].(string))
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
	if db, err := sql.Open("postgres", os.Getenv("DATABASE_URL")); err != nil {
		log.Fatalf("Error opening database: %q", err)
	} else {
		dp = &persistance.PostgreSqlDraftProvider{db}
	}

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
	domain := getEnv("AUTH0-DOMAIN", "http://localhost/")
	resp, err := http.Get(domain + ".well-known/jwks.json")

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
			jwk := jwks.Keys[k]

			if jwk.Kty != "RSA" {
				return cert, fmt.Errorf("invalid key type: %s", jwk.Kty)
			}

			nb, err := base64.RawURLEncoding.DecodeString(jwk.N)
			if err != nil {
				return cert, err
			}

			e := 0
			if jwk.E == "AQAB" || jwk.E == "AAEAAQ" {
				e = 65537
			} else {
				return cert, fmt.Errorf("unrecognized value for e: %s", jwk.E)
			}

			pk := &rsa.PublicKey{
				N: new(big.Int).SetBytes(nb),
				E: e,
			}

			der, err := x509.MarshalPKIXPublicKey(pk)
			if err != nil {
				return cert, err
			}

			block := &pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: der,
			}

			var out bytes.Buffer
			pem.Encode(&out, block)

			cert = out.String()
			break
		}
	}

	if cert == "" {
		err := errors.New("Unable to find appropriate key.")
		return cert, err
	}

	return cert, nil
}
