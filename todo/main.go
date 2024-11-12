package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
	"github.com/golang-jwt/jwt/v5"
)

var (
	KEYCLOAK_URL = "http://localhost:8080"
	REALM        = "myrealm"
	CLIENT_ID    = "example-test"
)

type TodoItem struct {
	ID   int    `json:"id"`
	Task string `json:"task"`
}

func main() {
	r := gin.Default()

	r.GET("/admin-todos", verifyAdminAccess, readAdminTodos)
	r.GET("/user-todos", readUserTodos)
	r.GET("/todos", verifyToken, readTodos)
	r.POST("/todos", verifyToken, createTodo)

	if err := r.Run(":8001"); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func verifyToken(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")

	client := resty.New()
	resp, err := client.R().
		SetHeader("Authorization", "Bearer "+token).
		Get(fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", KEYCLOAK_URL, REALM))

	if err != nil || resp.StatusCode() != http.StatusOK {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		c.Abort()
		return
	}

	c.Next()
}

func decodeToken(tokenString string) (*jwt.MapClaims, error) {
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*jwt.MapClaims)
	if !ok || claims == nil {
		return nil, fmt.Errorf("unable to parse claims")
	}

	return claims, nil
}

func verifyAdminAccess(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	token := strings.TrimPrefix(authHeader, "Bearer ")

	// Decode the JWT token to extract claims
	claims, err := decodeToken(token)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		c.Abort()
		return
	}

	fmt.Println("Claims:", claims)

	// Extract resource access
	resourceAccess, ok := (*claims)["resource_access"].(map[string]interface{})
	if !ok {
		c.JSON(http.StatusForbidden, gin.H{"error": "Resource access information missing"})
		c.Abort()
		return
	}

	fmt.Println("resourceAccess:", resourceAccess)

	// Access roles under 'example-test' key
	exampleTestAccess, ok := resourceAccess["example-test"].(map[string]interface{}) // Change here
	if !ok {
		c.JSON(http.StatusForbidden, gin.H{"error": "'example-test' resource access information missing"})
		c.Abort()
		return
	}

	fmt.Println("exampleTest:", exampleTestAccess)

	clientRoles, ok := exampleTestAccess["roles"].([]interface{})
	if !ok {
		c.JSON(http.StatusForbidden, gin.H{"error": "Roles information missing"})
		c.Abort()
		return
	}

	// Extract groups
	// groups, ok := (*claims)["groups"].([]interface{})
	// if !ok {
	// 	c.JSON(http.StatusForbidden, gin.H{"error": "Groups information missing"})
	// 	c.Abort()
	// 	return
	// }

	// Check for 'admin-clients' role or group
	hasAdminAccess := false
	for _, role := range clientRoles {
		if roleStr, ok := role.(string); ok && roleStr == "admin-clients" {
			hasAdminAccess = true
			break
		}
	}

	// for _, group := range groups {
	// 	if groupStr, ok := group.(string); ok && groupStr == "admin-clients" {
	// 		hasAdminAccess = true
	// 		break
	// 	}
	// }

	// If neither admin role nor group found, deny access
	if !hasAdminAccess {
		c.JSON(http.StatusForbidden, gin.H{"error": "Insufficient permissions"})
		c.Abort()
		return
	}

	// Store user info in context if admin access is verified
	c.Set("user_info", claims)
	c.Next()
}

func readAdminTodos(c *gin.Context) {
	adminTodos := []TodoItem{{ID: 1, Task: "Admin-only task"}}
	c.JSON(http.StatusOK, adminTodos)
}

func readUserTodos(c *gin.Context) {
	userTodos := []TodoItem{{ID: 2, Task: "General task for users"}}
	c.JSON(http.StatusOK, userTodos)
}

func readTodos(c *gin.Context) {
	todos := []TodoItem{
		{ID: 1, Task: "Buy milk"},
		{ID: 2, Task: "Write code"},
	}
	c.JSON(http.StatusOK, todos)
}

func createTodo(c *gin.Context) {
	var todo TodoItem
	if err := c.ShouldBindJSON(&todo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "Todo created", "todo": todo})
}
