package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/joho/godotenv"
)

type ReqUser struct {
	Email    string         `json:"email"`
	Password string         `json:"password"`
	About    map[string]any `json:"about"`
}

type RWError struct {
	Status  int    `json:"status"`
	Details string `json:"detail"`
}

type RWErrorWrapper struct {
	Errors []RWError `json:"errors"`
}

type RWUser struct {
	ID            string         `json:"id"`
	Email         string         `json:"email"`
	Token         string         `json:"token"`
	Created       string         `json:"createdAt"`
	Updated       string         `json:"updatedAt"`
	Role          string         `json:"role"`
	Provider      string         `json:"provider"`
	Organisation  []string       `json:"organizations"`
	Applications  []string       `json:"applications"`
	ExtraUserData map[string]any `json:"extraUserData"`
}

type RWUserWrapper struct {
	Data RWUser `json:"data"`
}

var (
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

	eaeAPIURL = os.Getenv("EAE_API_URL")
	callbackURL = os.Getenv("CALLBACK_URL")
	applicationName = os.Getenv("APP_NAME")
	preSharedKey = os.Getenv("AUTHENTICATOR_PSK")
	socketPath = os.Getenv("SOCKET")
}

func upsert(z RWUser, u ReqUser) (err error) {
	payload, _ := json.Marshal(map[string]any{
		"email": z.Email,
		"rwid":  z.ID,
		"about": u.About,
	})

	q, _ := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/authenticator_user_upsert", eaeAPIURL),
		bytes.NewBuffer(payload),
	)

	q.Header.Set("Content-Type", "application/json")
	q.Header.Set("Accept-Profile", "authenticator")
	q.Header.Set("x-authenticator-psk", preSharedKey)

	client := &http.Client{}

	resp, err := client.Do(q)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()

	if err != nil || resp.StatusCode != http.StatusOK {
		return err
	}

	return nil
}

func signup(w http.ResponseWriter, r *http.Request) {
	var u ReqUser

	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if u.Email == "" {
		http.Error(w, "Missing required fields: email", http.StatusBadRequest)
		return
	}

	payload, _ := json.Marshal(map[string]any{
		"email": u.Email,
		"apps":  []string{applicationName},
	})

	resp, err := http.Post(
		fmt.Sprintf("%s/auth/sign-up?callbackUrl=%s", resourceWatchURL, callbackURL),
		"application/json",
		bytes.NewReader(payload),
	)
	defer resp.Body.Close()

	if err != nil {
		http.Error(w, "Failed to create user on Resource Watch", http.StatusInternalServerError)
		return
	}

	body, _ := io.ReadAll(resp.Body)

	var x RWErrorWrapper

	if resp.StatusCode != http.StatusOK {
		json.Unmarshal(body, &x)
		http.Error(w, x.Errors[0].Details, x.Errors[0].Status)
		return
	}

	var y RWUserWrapper
	json.Unmarshal(body, &y)

	if err = upsert(y.Data, u); err != nil {
		http.Error(w, "Failed to sync user data to EAE service", http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "User registered successfully! Please check your email inbox to activate your account.")
}

func login(w http.ResponseWriter, r *http.Request) {
	var u ReqUser

	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if u.Email == "" || u.Password == "" {
		http.Error(w, "Missing required fields: email, password", http.StatusBadRequest)
		return
	}

	payload, _ := json.Marshal(map[string]string{
		"email":    u.Email,
		"password": u.Password,
	})

	resp, err = http.Post(
		fmt.Sprintf("%s/auth/login", resourceWatchURL),
		"application/json",
		bytes.NewReader(payload),
	)
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var y RWUserWrapper
	json.Unmarshal(body, &y)
	z := y.Data

	if err = upsert(y.Data, u); err != nil {
		http.Error(w, "Failed to sync user data to EAE service", http.StatusInternalServerError)
		return
	}

	j, _ := json.Marshal(map[string]string{"token": z.Token})

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, string(j))
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
