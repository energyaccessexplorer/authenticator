package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
	"github.com/pkg/errors"
)

var (
	RESOURCE_WATCH_API_URL = "https://api.resourcewatch.org"
	JWT_SECRET             string
	MAC_SECRET_KEY         string
	CALLBACK_URL           string
	APP_NAME               string
)

// Struct for account payload
type AccountPayload struct {
	Email string   `json:"email"`
	Name  string   `json:"name"`
	Apps  []string `json:"apps"`
}

// Struct to handle signup request
type SignupRequest struct {
	Email    string `json:"email"`
	JsonData struct {
		FirstName string `json:"first_name"`
	} `json:"jsondata"`
}

// Struct to handle login request
type LoginRequest struct {
	Email    string `json:"password"`
	Password string `json:"password"`
}

// Struct for user data
type User struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Role  string `json:"role"`
	Data  struct {
		FirstName string `json:"first_name"`
	} `json:"data"`
}

// Struct for Resource Watch sign-up response
type SignupResponse struct {
	Data struct {
		ID string `json:"id"`
	} `json:"data"`
}

// Struct for Resource Watch login response
type LoginResponse struct {
	Data struct {
		Sub string `json:"sub"`
	} `json:"data"`
}

// Struct for response formatting
type Response struct {
	Error   string `json:"error,omitempty"`
	Details string `json:"details,omitempty"`
	Token   string `json:"token,omitempty"`
	Data    string `json:"data,omitempty"`
}

func init() {
	// Load .env file for environment variables
	if err := godotenv.Load(); err != nil {
		log.Fatal("Error loading .env file")
	}
	JWT_SECRET = os.Getenv("PGREST_SECRET")
	MAC_SECRET_KEY = os.Getenv("MAC_SECRET_KEY")
	CALLBACK_URL = os.Getenv("CALLBACK_URL")
	APP_NAME = os.Getenv("APP_NAME")
}

func main() {
	r := mux.NewRouter()
	r.HandleFunc("/signup", signupHandler).Methods("POST")
	r.HandleFunc("/login", loginHandler).Methods("POST")
	http.Handle("/", r)

	log.Println("Server started at http://localhost:5003")
	log.Fatal(http.ListenAndServe(":5003", nil))
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	var signupRequest SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&signupRequest); err != nil {
		http.Error(w, fmt.Sprintf("Error decoding request: %s", err), http.StatusBadRequest)
		return
	}

	if signupRequest.Email == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	accountPayload := AccountPayload{
		Email: signupRequest.Email,
		Name:  signupRequest.JsonData.FirstName,
		Apps:  []string{APP_NAME},
	}

	// Make request to Resource Watch API
	resp, err := makeAPIRequest(http.MethodPost, "/auth/sign-up?callbackUrl="+CALLBACK_URL, accountPayload)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error signing up: %v", err), http.StatusInternalServerError)
		return
	}

	var signupResponse SignupResponse
	if err := json.Unmarshal(resp, &signupResponse); err != nil {
		http.Error(w, "Error parsing response from Resource Watch", http.StatusInternalServerError)
		return
	}

	newUser := User{
		Sub:   signupResponse.Data.ID,
		Email: signupRequest.Email,
		Role:  "guest",
		Data: struct {
			FirstName string `json:"first_name"`
		}{FirstName: signupRequest.JsonData.FirstName}, // Initialize the nested struct
	}

	// @TODO: Save the new user to PostgREST
	fmt.Println(newUser)

	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, "User registered successfully! Please check your email inbox to activate your account.")
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	var loginRequest LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		http.Error(w, fmt.Sprintf("Error decoding request: %s", err), http.StatusBadRequest)
		return
	}

	if loginRequest.Email == "" || loginRequest.Password == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	payload := map[string]string{
		"email":    loginRequest.Email,
		"password": loginRequest.Password,
	}
	fmt.Println(payload)

	// Make request to Resource Watch API
	resp, err := makeAPIRequest(http.MethodPost, "/auth/login", payload)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error logging in: %v", err), http.StatusInternalServerError)
		return
	}

	var loginResponse LoginResponse
	if err := json.Unmarshal(resp, &loginResponse); err != nil {
		http.Error(w, "Error parsing response from Resource Watch", http.StatusInternalServerError)
		return
	}

	fmt.Println(loginResponse)
	sub := loginResponse.Data.Sub

	// @TODO: Get user from PostgREST
	user := User{
		Sub:   sub,
		Email: loginRequest.Email,
		Role:  "guest",
	}

	token, err := generateJWT(user)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error generating token: %v", err), http.StatusInternalServerError)
		return
	}

	response := Response{
		Token: token,
		Data:  fmt.Sprintf("%v", loginResponse), // Include entire login response (optional)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func makeAPIRequest(method, path string, payload interface{}) ([]byte, error) {
	client := &http.Client{}
	url := RESOURCE_WATCH_API_URL + path

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal request payload")
	}

	req, err := http.NewRequest(method, url, strings.NewReader(string(body)))
	if err != nil {
		return nil, errors.Wrap(err, "failed to create request")
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to send request")
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read response body")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status: %d", resp.StatusCode)
	}

	return respBody, nil
}

func generateJWT(user User) (string, error) {
	claims := jwt.MapClaims{
		"sub":   user.Sub,
		"name":  user.Data.FirstName,
		"email": user.Email,
		"role":  user.Role,
		"data":  user.Data,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(JWT_SECRET))
	if err != nil {
		return "", errors.Wrap(err, "failed to sign token")
	}

	return tokenString, nil
}
