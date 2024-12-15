package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
)

type RegisterUserRequest struct {
	Email    string         `json:"email"`
	JsonData map[string]any `json:"jsondata"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type JWTClaims struct {
	Email string         `json:"email"`
	Role  string         `json:"role"`
	Data  map[string]any `json:"data"`
	ID    string         `json:"id"`
	jwt.RegisteredClaims
}

var (
	jwtSecretKey     string
	resourceWatchURL string
	eaeAPIURL        string
	callbackURL      string
	applicationName  string
	preSharedKey     string
	socketPath       string
)

func loadEnv() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, loading defaults.")
	}

	resourceWatchURL = "https://api.resourcewatch.org"

	jwtSecretKey = os.Getenv("JWT_SECRET")
	eaeAPIURL = os.Getenv("EAE_API_URL")
	callbackURL = os.Getenv("CALLBACK_URL")
	applicationName = os.Getenv("APP_NAME")
	preSharedKey = os.Getenv("AUTHENTICATOR_PSK")
	socketPath = os.Getenv("SOCKET")
}

func signup(w http.ResponseWriter, r *http.Request) {
	var req RegisterUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.JsonData == nil {
		http.Error(w, "Missing required fields: email, jsondata", http.StatusBadRequest)
		return
	}

	payload, _ := json.Marshal(map[string]any{
		"email": req.Email,
		"name":  req.JsonData["first_name"],
		"apps":  []string{applicationName},
	})

	resp, err := http.Post(
		fmt.Sprintf("%s/auth/sign-up?callbackUrl=%s", resourceWatchURL, callbackURL),
		"application/json",
		bytes.NewReader(payload),
	)
	defer resp.Body.Close()

	if err != nil || resp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to create user on Resource Watch", http.StatusInternalServerError)
		return
	}

	eaePayload := map[string]any{
		"email": req.Email,
		"role":  "guest",
		"data":  req.JsonData,
	}

	eaePayloadJSON, _ := json.Marshal(eaePayload)

	q, _ := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/authenticator_user_upsert", eaeAPIURL),
		bytes.NewBuffer(eaePayloadJSON),
	)

	q.Header.Set("Content-Type", "application/json")
	q.Header.Set("Accept-Profile", "authenticator")
	q.Header.Set("x-authenticator-psk", preSharedKey)

	client := &http.Client{}

	resp, err = client.Do(q)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if err != nil || resp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to sync user data to EAE service", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "User registered successfully! Please check your email inbox to activate your account.")
}

func login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		http.Error(w, "Missing required fields: email, password", http.StatusBadRequest)
		return
	}

	resp, err := http.Get(fmt.Sprintf("%s/users?email=eq.%s", eaeAPIURL, req.Email))
	defer resp.Body.Close()

	if err != nil || resp.StatusCode != http.StatusOK {
		http.Error(w, "Failed to fetch user data from EAE service", http.StatusInternalServerError)
		return
	}

	authPayload := map[string]string{
		"email":    req.Email,
		"password": req.Password,
	}

	authPayloadJSON, _ := json.Marshal(authPayload)

	authResp, err := http.Post(
		fmt.Sprintf("%s/auth/login", resourceWatchURL),
		"application/json",
		bytes.NewReader(authPayloadJSON),
	)
	defer authResp.Body.Close()

	if err != nil || authResp.StatusCode != http.StatusOK {
		http.Error(w, "Authentication failed with Resource Watch", http.StatusUnauthorized)
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, JWTClaims{
		Email: req.Email,
		Role:  "guest",
		Data:  map[string]any{"example": "data"},
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
	mux.HandleFunc("/signup", signup)
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
