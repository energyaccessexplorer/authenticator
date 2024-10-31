package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/joho/godotenv"
)

var jwtSecret []byte
var rwAPIKey []byte
var callbackURL string
var appName string

const resourceWatchAPIURL = "https://api.resourcewatch.org"

// Custom claim structure for JWT
type CustomClaims struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
	Role  string `json:"role"`
	jwt.RegisteredClaims
}

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatalf("Error loading .env file")
	}
	jwtSecret = []byte(os.Getenv("PGREST_SECRET"))
	rwAPIKey = []byte(os.Getenv("RW_API_KEY"))
	callbackURL = os.Getenv("CALLBACK_URL")
	appName = os.Getenv("APP_NAME")
}

func main() {
	router := mux.NewRouter()

	// Handle routes
	router.HandleFunc("/signup", createUser).Methods("POST")
	router.HandleFunc("/login", loginUser).Methods("POST")

	// CORS configuration
	corsAllowedOrigins := handlers.AllowedOrigins([]string{"http://eae.localhost", "https://*.energyaccessexplorer.org"})
	corsAllowedMethods := handlers.AllowedMethods([]string{"GET", "POST"})

	log.Println("Server running on port 5001")
	log.Fatal(http.ListenAndServe(":5001", handlers.CORS(corsAllowedOrigins, corsAllowedMethods)(router)))
}

func createUser(w http.ResponseWriter, r *http.Request) {
	var requestData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid JSON request body", http.StatusBadRequest)
		return
	}

	email, emailExists := requestData["email"].(string)
	jsondata, jsonExists := requestData["jsondata"].(map[string]interface{})
	if !emailExists || !jsonExists {
		http.Error(w, `{"error": "Missing required fields"}`, http.StatusBadRequest)
		return
	}

	payload := map[string]interface{}{
		"email":     email,
		"firstName": jsondata["first_name"],
		"lastName":  jsondata["last_name"],
		"apps":      []string{appName},
		"applicationData": map[string]interface{}{
			"gfw": map[string]interface{}{
				"role":              "guest",
				"organization":      jsondata["organization"],
				"job_title":         jsondata["job_title"],
				"gender":            jsondata["gender"],
				"city":              jsondata["city"],
				"areas_of_interest": jsondata["areas_of_interest"],
				"country":           jsondata["country"],
				"account":           jsondata["account"],
				"mailing":           jsondata["mailing"],
			},
		},
	}

	client := &http.Client{}
	reqBody, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/auth/sign-up?callbackUrl=%s", resourceWatchAPIURL, callbackURL), bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", string(rwAPIKey))

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, `{"error": "An error occurred"}`, http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusCreated {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"message": "User created successfully"}`))
	} else {
		var responseBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&responseBody)
		response, _ := json.Marshal(map[string]interface{}{
			"error":   "Failed to create user",
			"details": responseBody,
		})
		w.WriteHeader(resp.StatusCode)
		w.Write(response)
	}
}

func loginUser(w http.ResponseWriter, r *http.Request) {
	var requestData map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&requestData); err != nil {
		http.Error(w, "Invalid JSON request body", http.StatusBadRequest)
		return
	}

	email, emailExists := requestData["email"].(string)
	password, passwordExists := requestData["password"].(string)
	if !emailExists || !passwordExists {
		http.Error(w, `{"error": "Missing required field"}`, http.StatusBadRequest)
		return
	}

	payload := map[string]interface{}{
		"email":    email,
		"password": password,
	}

	client := &http.Client{}
	reqBody, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", fmt.Sprintf("%s/auth/login", resourceWatchAPIURL), bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", string(rwAPIKey))

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, `{"error": "An error occurred"}`, http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var responseData map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&responseData)

		id := uuid.NewSHA1(uuid.NameSpaceX500, []byte(responseData["id"].(string)))
		claims := CustomClaims{
			ID:    id.String(),
			Name:  "Name", // @TODO get from applicationData
			Email: responseData["email"].(string),
			Role:  "guest", // @TODO get from applicationData
			RegisteredClaims: jwt.RegisteredClaims{
				IssuedAt:  jwt.NewNumericDate(time.Now()),
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Minute)),
			},
		}
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtSecret)
		if err != nil {
			http.Error(w, `{"error": "An error occurred"}`, http.StatusInternalServerError)
			return
		}

		response, _ := json.Marshal(map[string]interface{}{
			"token": tokenString,
			"data":  responseData,
		})
		w.WriteHeader(http.StatusOK)
		w.Write(response)
	} else {
		var responseBody map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&responseBody)
		response, _ := json.Marshal(map[string]interface{}{
			"error":   "Failed to login",
			"details": responseBody,
		})
		w.WriteHeader(resp.StatusCode)
		w.Write(response)
	}
}
