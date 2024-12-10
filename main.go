package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
	"github.com/joho/godotenv"
)

type RegisterUserRequest struct {
	Email    string                 `json:"email"`
	JsonData map[string]interface{} `json:"jsondata"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type JWTClaims struct {
	Email string                 `json:"email"`
	Role  string                 `json:"role"`
	Data  map[string]interface{} `json:"data"`
	ID    string                 `json:"id"`
	jwt.StandardClaims
}

var (
	jwtSecretKey     string
	resourceWatchURL string
	eaeAPIURL        string
	callbackURL      string
	applicationName  string
	preSharedKey     string
	socketPath       = "/tmp/server.sock"
)

func loadEnv() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, loading defaults.")
	}

	jwtSecretKey = os.Getenv("PGREST_SECRET")
	resourceWatchURL = "https://api.resourcewatch.org"
	eaeAPIURL = os.Getenv("EAE_API_URL")
	callbackURL = os.Getenv("CALLBACK_URL")
	applicationName = os.Getenv("APP_NAME")
	preSharedKey = os.Getenv("PSK")
}

func validateHeaders(r *http.Request) error {
	if r.Header.Get("x-authenticator-psk") != preSharedKey {
		return errors.New("invalid PSK")
	}
	if r.Header.Get("Accept-Profile") != "authenticator" {
		return errors.New("invalid profile")
	}
	return nil
}

func registerUser(w http.ResponseWriter, r *http.Request) {
	if err := validateHeaders(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var req RegisterUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.JsonData == nil {
		http.Error(w, "Missing required fields: email, jsondata", http.StatusBadRequest)
		return
	}

	userPayload := map[string]interface{}{
		"email": req.Email,
		"name":  req.JsonData["first_name"],
		"apps":  []string{applicationName},
	}

	userPayloadJSON, _ := json.Marshal(userPayload)

	resp, err := http.Post(fmt.Sprintf("%s/auth/sign-up?callbackUrl=%s", resourceWatchURL, callbackURL),
		"application/json", bytes.NewReader(userPayloadJSON))
	if err != nil || resp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to create user on Resource Watch", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	eaePayload := map[string]interface{}{
		"email": req.Email,
		"role":  "guest",
		"data":  req.JsonData,
	}

	eaePayloadJSON, _ := json.Marshal(eaePayload)

	resp, err = http.Post(fmt.Sprintf("%s/authenticator_user_upsert", eaeAPIURL),
		"application/json", bytes.NewReader(eaePayloadJSON))
	if err != nil || resp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to sync user data to EAE service", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	fmt.Fprintln(w, "User registered successfully! Please check your email inbox to activate your account.")
}

func login(w http.ResponseWriter, r *http.Request) {
	if err := validateHeaders(r); err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, "Missing required fields: email, password", http.StatusBadRequest)
		return
	}

	eaeURL := fmt.Sprintf("%s/users?email=eq.%s", eaeAPIURL, req.Email)
	resp, err := http.Get(eaeURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to fetch user data from EAE service", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	authPayload := map[string]string{
		"email":    req.Email,
		"password": req.Password,
	}
	authPayloadJSON, _ := json.Marshal(authPayload)

	authResp, err := http.Post(fmt.Sprintf("%s/auth/login", resourceWatchURL),
		"application/json", bytes.NewReader(authPayloadJSON))
	if err != nil || authResp.StatusCode != http.StatusOK {
		http.Error(w, "Authentication failed with Resource Watch", http.StatusUnauthorized)
		return
	}
	defer authResp.Body.Close()

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTClaims{
		Email: req.Email,
		Role:  "guest",
		Data:  map[string]interface{}{"example": "data"},
	})
	tokenString, err := token.SignedString([]byte(jwtSecretKey))
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"token": tokenString})
}

func main() {
	loadEnv()

	mux := http.NewServeMux()
	mux.HandleFunc("/signup", registerUser)
	mux.HandleFunc("/login", login)

	if _, err := os.Stat(socketPath); err == nil {
		os.Remove(socketPath)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		log.Fatalf("Failed to listen on socket: %v", err)
	}
	defer listener.Close()

	log.Printf("Server is listening on %s", socketPath)
	if err := http.Serve(listener, mux); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
