package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
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
	RW_URL            = os.Getenv("RW_URL")
	EAE_URL           = os.Getenv("EAE_URL")
	CALLBACK_URL      = os.Getenv("CALLBACK_URL")
	APP_NAME          = os.Getenv("APP_NAME")
	AUTHENTICATOR_PSK = os.Getenv("AUTHENTICATOR_PSK")
	SOCKET            = os.Getenv("SOCKET")
)

func upsert(z RWUser, u ReqUser) (err error) {
	payload, err := json.Marshal(map[string]any{
		"email": z.Email,
		"rwid":  z.ID,
		"about": u.About,
	})

	q, err := http.NewRequest(
		"POST",
		fmt.Sprintf("%s/rpc/user_upsert", EAE_URL),
		bytes.NewBuffer(payload),
	)

	if err != nil {
		return err
	}

	q.Header.Set("Content-Type", "application/json")
	q.Header.Set("Content-Profile", "authenticator")
	q.Header.Set("x-authenticator-psk", AUTHENTICATOR_PSK)

	client := &http.Client{}

	resp, err := client.Do(q)

	if err != nil {
		return err
	}

	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return errors.New(fmt.Sprintf("%d: %s", resp.StatusCode, body))
	}

	return nil
}

func signup(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "OPTIONS":
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusOK)
		return
	}

	var u ReqUser

	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	payload, _ := json.Marshal(map[string]any{
		"email": u.Email,
		"apps":  []string{APP_NAME},
	})

	resp, err := http.Post(
		fmt.Sprintf("%s/auth/sign-up?callbackUrl=%s", RW_URL, CALLBACK_URL),
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	fmt.Fprintln(w, "User registered successfully! Please check your email inbox to activate your account.")
}

func login(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "OPTIONS":
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusOK)
		return
	}

	var u ReqUser

	if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	payload, _ := json.Marshal(map[string]string{
		"email":    u.Email,
		"password": u.Password,
	})

	resp, err := http.Post(
		fmt.Sprintf("%s/auth/login", RW_URL),
		"application/json",
		bytes.NewReader(payload),
	)
	defer resp.Body.Close()

	if err != nil {
		http.Error(w, "Failed to login at Resource Watch", http.StatusInternalServerError)
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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	j, _ := json.Marshal(map[string]string{"token": y.Data.Token})

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintln(w, string(j))
}

func main() {
	if RW_URL == "" {
		panic("RW_URL env variable is required")
	}

	if EAE_URL == "" {
		panic("EAE_URL env variable is required")
	}

	if CALLBACK_URL == "" {
		panic("CALLBACK_URL env variable is required")
	}

	if APP_NAME == "" {
		panic("APP_NAME env variable is required")
	}

	if AUTHENTICATOR_PSK == "" {
		panic("AUTHENTICATOR_PSK env variable is required")
	}

	if SOCKET == "" {
		panic("SOCKET env variable is required")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/signup", signup)
	mux.HandleFunc("/login", login)

	if _, err := os.Stat(SOCKET); err == nil {
		os.Remove(SOCKET)
	}

	listener, err := net.Listen("unix", SOCKET)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}
	defer listener.Close()

	os.Chmod(SOCKET, 0777)

	log.Printf("Server is listening on %s", SOCKET)

	if err := http.Serve(listener, mux); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
