package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"

	"net/http"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

type AppConfig struct {
	ServerSocket     string
	EAEApiBaseURL    string
	ResourceWatchURL string
	JWTSecretKey     string
	PreSharedKey     string
	CallbackURL      string
	ApplicationName  string
	AllowedOrigins   string
}

type UserPayload struct {
	Email string   `json:"email"`
	Name  string   `json:"name"`
	Apps  []string `json:"apps"`
}

type JSONData struct {
	FirstName string `json:"first_name"`
}

type RegisterRequest struct {
	Email    string   `json:"email"`
	JSONData JSONData `json:"jsondata"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func loadConfig() (*AppConfig, error) {
	if err := godotenv.Load(); err != nil {
		return nil, err
	}

	return &AppConfig{
		ServerSocket:     os.Getenv("SOCKET"),
		EAEApiBaseURL:    os.Getenv("EAE_API_URL"),
		ResourceWatchURL: "https://api.resourcewatch.org",
		JWTSecretKey:     os.Getenv("PGREST_SECRET"),
		PreSharedKey:     os.Getenv("PSK"),
		CallbackURL:      os.Getenv("CALLBACK_URL"),
		ApplicationName:  os.Getenv("APP_NAME"),
		AllowedOrigins:   os.Getenv("ALLOWED_ORIGINS"),
	}, nil
}

func marshalJSON(data interface{}) io.Reader {
	jsonData, _ := json.Marshal(data)
	return strings.NewReader(string(jsonData))
}

func validateRequiredFields(data map[string]interface{}, fields []string) error {
	missingFields := []string{}
	for _, field := range fields {
		if _, exists := data[field]; !exists {
			missingFields = append(missingFields, field)
		}
	}
	if len(missingFields) > 0 {
		return errors.New("Missing required fields: " + strings.Join(missingFields, ", "))
	}
	return nil
}

func registerUser(config *AppConfig, conn net.Conn, requestBody io.Reader) {
	var registerRequest RegisterRequest
	if err := json.NewDecoder(requestBody).Decode(&registerRequest); err != nil {
		conn.Write([]byte(fmt.Sprintf(`{"error": "Invalid request payload: %s"}`, err.Error())))
		return
	}

	requiredFields := []string{"email", "jsondata"}
	requestMap := map[string]interface{}{
		"email":    registerRequest.Email,
		"jsondata": registerRequest.JSONData,
	}
	if err := validateRequiredFields(requestMap, requiredFields); err != nil {
		conn.Write([]byte(fmt.Sprintf(`{"error": "%s"}`, err.Error())))
		return
	}

	userPayload := UserPayload{
		Email: registerRequest.Email,
		Name:  registerRequest.JSONData.FirstName,
		Apps:  []string{config.ApplicationName},
	}

	signupURL := fmt.Sprintf("%s/auth/sign-up?callbackUrl=%s", config.ResourceWatchURL, config.CallbackURL)
	response, err := http.Post(signupURL, "application/json", marshalJSON(userPayload))
	if err != nil || response.StatusCode >= 300 {
		conn.Write([]byte(`{"error": "Failed to create user on Resource Watch."}`))
		return
	}

	syncData := map[string]interface{}{
		"email": registerRequest.Email,
		"role":  "guest",
		"data":  registerRequest.JSONData,
	}
	eaeURL := fmt.Sprintf("%s/authenticator_user_upsert", config.EAEApiBaseURL)
	eaeResponse, err := http.Post(eaeURL, "application/json", marshalJSON(syncData))
	if err != nil || eaeResponse.StatusCode >= 300 {
		conn.Write([]byte(`{"error": "Failed to sync user data to EAE service."}`))
		return
	}

	conn.Write([]byte("User registered successfully! Please check your email inbox to activate your account."))
}

func loginUser(config *AppConfig, conn net.Conn, requestBody io.Reader) {
	var loginRequest LoginRequest
	if err := json.NewDecoder(requestBody).Decode(&loginRequest); err != nil {
		conn.Write([]byte(fmt.Sprintf(`{"error": "Invalid request payload: %s"}`, err.Error())))
		return
	}

	requiredFields := []string{"email", "password"}
	requestMap := map[string]interface{}{
		"email":    loginRequest.Email,
		"password": loginRequest.Password,
	}
	if err := validateRequiredFields(requestMap, requiredFields); err != nil {
		conn.Write([]byte(fmt.Sprintf(`{"error": "%s"}`, err.Error())))
		return
	}

	userDBURL := fmt.Sprintf("%s/authenticator_user_select?email=eq.%s", config.EAEApiBaseURL, loginRequest.Email)
	resp, err := http.Get(userDBURL)
	if err != nil || resp.StatusCode >= 300 {
		conn.Write([]byte(`{"error": "Failed to fetch user data."}`))
		return
	}

	var userDBData []map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&userDBData); err != nil {
		conn.Write([]byte(fmt.Sprintf(`{"error": "Failed to parse user data: %s"}`, err.Error())))
		return
	}

	loginPayload := map[string]string{
		"email":    loginRequest.Email,
		"password": loginRequest.Password,
	}
	authResp, err := http.Post(fmt.Sprintf("%s/auth/login", config.ResourceWatchURL), "application/json", marshalJSON(loginPayload))
	if err != nil || authResp.StatusCode == 401 {
		if len(userDBData) == 0 {
			conn.Write([]byte(`{"error": "Unauthorized", "detail": "Invalid email/password combination."}`))
			return
		}

		migrationPayload := UserPayload{
			Email: userDBData[0]["email"].(string),
			Name:  userDBData[0]["data"].(map[string]interface{})["first_name"].(string),
			Apps:  []string{config.ApplicationName},
		}
		_, migrationErr := http.Post(fmt.Sprintf("%s/auth/sign-up?callbackUrl=%s", config.ResourceWatchURL, config.CallbackURL), "application/json", marshalJSON(migrationPayload))
		if migrationErr != nil {
			conn.Write([]byte(`{"error": "Migration failed. Please try again later."}`))
			return
		}
		conn.Write([]byte(`{"error": "Migrated", "detail": "Please check your email to reactivate your account."}`))
		return
	}

	if authResp.StatusCode == 200 {
		jwtPayload := map[string]interface{}{
			"email": userDBData[0]["email"],
			"role":  userDBData[0]["role"],
			"data":  userDBData[0]["data"],
			"id":    userDBData[0]["id"],
		}
		jwtToken, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(jwtPayload)).SignedString([]byte(config.JWTSecretKey))
		if err != nil {
			conn.Write([]byte(`{"error": "Failed to generate JWT."}`))
			return
		}
		response := map[string]interface{}{
			"token": jwtToken,
			"data":  jwtPayload["data"],
		}
		conn.Write(marshalJSON(response))
		return
	}

	conn.Write([]byte(`{"error": "Login failed. Please try again later."}`))
}

func handleConnection(config *AppConfig, conn net.Conn) {
	defer conn.Close()
	var request map[string]interface{}
	if err := json.NewDecoder(conn).Decode(&request); err != nil {
		conn.Write([]byte(fmt.Sprintf(`{"error": "Failed to parse request: %s"}`, err.Error())))
		return
	}

	action, exists := request["action"]
	if !exists {
		conn.Write([]byte(`{"error": "Missing 'action' in request."}`))
		return
	}

	switch action {
	case "register":
		registerUser(config, conn, marshalJSON(request["data"]))
	case "login":
		loginUser(config, conn, marshalJSON(request["data"]))
	default:
		conn.Write([]byte(`{"error": "Unknown action."}`))
	}
}

func main() {
	config, err := loadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %s", err.Error())
	}

	listener, err := net.Listen("unix", config.ServerSocket)
	if err != nil {
		log.Fatalf("Failed to start server on socket: %s", err.Error())
	}
	defer os.Remove(config.ServerSocket)

	log.Printf("Server is running on socket: %s", config.ServerSocket)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %s", err.Error())
			continue
		}

		go handleConnection(config, conn)
	}
}
