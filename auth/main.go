package main

import (
	"context"
	"net/http"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gin-gonic/gin"
)

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type LoginResponse struct {
	AccessToken string `json:"access_token"`
}

var (
	keycloakURL  = "http://localhost:8080"
	clientID     = "example-test"
	realmName    = "myrealm"
	clientSecret = "oAMMhVEPzx0RI908LWFNFFtQvHmtdayJ" // Replace with actual client secret
	keycloak     = gocloak.NewClient(keycloakURL)
)

func main() {
	router := gin.Default()

	router.POST("/login", loginHandler)
	router.GET("/userinfo", getUserInfo)

	router.Run(":8000")
}

func loginHandler(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
		return
	}

	ctx := context.Background()
	token, err := keycloak.Login(ctx, clientID, clientSecret, realmName, req.Username, req.Password)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	response := LoginResponse{
		AccessToken: token.AccessToken,
	}

	c.JSON(http.StatusOK, response)
}

func getUserInfo(c *gin.Context) {
	token := c.GetHeader("Authorization")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})
		return
	}

	ctx := context.Background()
	userInfo, err := keycloak.GetUserInfo(ctx, token, realmName)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Directly return userInfo since it’s already a struct
	c.JSON(http.StatusOK, userInfo)
}
