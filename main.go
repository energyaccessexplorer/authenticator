package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var db *gorm.DB
var port string
var jwtSecret string
var resourceWatchAPIUrl string
var appName string
var callbackUrl string

type User struct {
	ID     uint            `gorm:"primaryKey"`
	UserID string          `gorm:"unique;not null"`
	Email  string          `gorm:"unique;not null"`
	Role   string          `gorm:"not null"`
	Data   json.RawMessage `gorm:"type:json"`
}

type SignupRequest struct {
	Email    string                 `json:"email"`
	JsonData map[string]interface{} `json:"jsondata"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func init() {
	dotenv_err := godotenv.Load()
	if dotenv_err != nil {
		log.Fatalf("Error loading .env file")
	}

	port = os.Getenv("PORT")
	jwtSecret = os.Getenv("PGREST_SECRET")
	resourceWatchAPIUrl = "https://api.resourcewatch.org"
	appName = os.Getenv("APP_NAME")
	callbackUrl = os.Getenv("CALLBACK_URL")

	dsn := os.Getenv("DATABASE_URI")
	fmt.Println("Database URI:", dsn)

	fmt.Println(dsn)
	var err error
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	db.AutoMigrate(&User{})
}

func createUser(c *gin.Context) {
	var req SignupRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required fields"})
		return
	}

	accountPayload := map[string]interface{}{
		"email": req.Email,
		"name":  req.JsonData["first_name"],
		"apps":  []string{appName},
	}

	accountPayloadBytes, err := json.Marshal(accountPayload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode JSON payload"})
		return
	}
	response, err := http.Post(fmt.Sprintf("%s/auth/sign-up?callbackUrl=%s", resourceWatchAPIUrl, callbackUrl), "application/json", strings.NewReader(string(accountPayloadBytes)))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An error occurred", "details": err.Error()})
		return
	}
	defer response.Body.Close()

	var responseData map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&responseData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse response data"})
		return
	}

	userID := responseData["data"].(map[string]interface{})["id"].(string)
	uuidV5 := uuid.NewSHA1(uuid.NameSpaceX500, []byte(userID))

	// Convert JsonData to json.RawMessage
	jsonData, err := json.Marshal(req.JsonData)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode JSON data"})
		return
	}

	newUser := User{
		UserID: uuidV5.String(),
		Email:  req.Email,
		Role:   "guest",
		Data:   json.RawMessage(jsonData),
	}

	if err := db.Create(&newUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An error occurred", "details": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully! Please check your email inbox to activate your account."})
}

func login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing required field"})
		return
	}

	payload := map[string]interface{}{
		"email":    req.Email,
		"password": req.Password,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to encode JSON payload"})
		return
	}
	response, err := http.Post(fmt.Sprintf("%s/auth/login", resourceWatchAPIUrl), "application/json", strings.NewReader(string(payloadBytes)))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "An error occurred", "details": err.Error()})
		return
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		c.JSON(response.StatusCode, gin.H{"error": "Failed to login"})
		return
	}

	var responseData map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&responseData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse response data"})
		return
	}
	data := responseData["data"].(map[string]interface{})

	userID := data["id"].(string)
	uuidV5 := uuid.NewSHA1(uuid.NameSpaceX500, []byte(userID))

	var user User
	if err := db.First(&user, "user_id = ?", uuidV5.String()).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not found"})
		return
	}

	var userData map[string]interface{}
	if err := json.Unmarshal(user.Data, &userData); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse user data"})
		return
	}

	tokenPayload := jwt.MapClaims{
		"id":       user.UserID,
		"name":     userData["first_name"],
		"email":    user.Email,
		"role":     user.Role,
		"data":     userData,
		"rw_token": data["token"],
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, tokenPayload)
	tokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": tokenString, "data": data})
}

func main() {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{"http://eae.localhost", "https://*.energyaccessexplorer.org"},
		AllowMethods: []string{"GET", "POST"},
	}))

	r.POST("/signup", createUser)
	r.POST("/login", login)

	if err := r.Run(port); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
