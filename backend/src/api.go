package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/mux"
)

type ApiResponse struct {
	Message string `json:"message"`
	Data    any    `json:"data"`
}

func makeResponse(w http.ResponseWriter, responseStatus int, message string, data any) {
	w.Header().Add("content-type", "application/json")
	w.WriteHeader(responseStatus)
	json.NewEncoder(w).Encode(ApiResponse{
		Message: message,
		Data:    data,
	})
}

func permissionDenied(w http.ResponseWriter, message string) {
	makeResponse(w, http.StatusUnauthorized, message, nil)
}

func serverError(w http.ResponseWriter, errorMessage string) {
	makeResponse(w, http.StatusInternalServerError, errorMessage, nil)
}

type ApiServer struct {
	listenAddr    string
	adminUsername string
	adminPassword string
	jwtSecret     string
	configPath    string
	logger        *log.Logger
}

func NewApiServer(listenAddr, adminUsername, adminPassword, jwtSecret, configPath string, loggerOut io.Writer) *ApiServer {

	return &ApiServer{
		listenAddr:    listenAddr,
		adminUsername: adminUsername,
		adminPassword: adminPassword,
		jwtSecret:     jwtSecret,
		configPath:    configPath,
		logger:        log.New(loggerOut, log.Prefix(), log.Flags()),
	}
}

func (s *ApiServer) Run() {
	router := mux.NewRouter()

	router.HandleFunc("/api/login", s.handleLogin)
	router.HandleFunc("/api/client", s.withJWTAuth(s.handleClient))
	s.logger.Fatal(http.ListenAndServe(s.listenAddr, router))
}

/*
Login logic
*/

func (s *ApiServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")
	s.logger.Println("new login", username, password)
	if s.adminUsername == username && s.adminPassword == password {
		token, err := createJWT(username, s.jwtSecret)
		if err != nil {
			serverError(w, err.Error())
			return
		}
		w.Header().Add("x-jwt-token", token)
		makeResponse(w, http.StatusOK, "login successful", nil)
		return
	}
	permissionDenied(w, "incorrect username or password")
}

func createJWT(username, jwtSecret string) (string, error) {
	claims := &jwt.MapClaims{
		"expiresAt": 15000,
		"username":  username,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(jwtSecret))
}

func (s *ApiServer) validateJWT(tokenString string) (*jwt.Token, error) {
	secret := s.jwtSecret

	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return []byte(secret), nil
	})
}

func (s *ApiServer) withJWTAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenString := r.Header.Get("x-jwt-token")
		token, err := s.validateJWT(tokenString)
		if err != nil {
			permissionDenied(w, err.Error())
			return
		}
		if !token.Valid {
			permissionDenied(w, "token is not valid")
			return
		}

		next(w, r)
	}
}

/*
Clients logic
*/

func (s *ApiServer) handleClient(w http.ResponseWriter, r *http.Request) {
	clients, err := ReadConfigFile(s.configPath)
	if err != nil {
		serverError(w, err.Error())
		return
	}

	// Method GET
	if r.Method == http.MethodGet {
		makeResponse(w, http.StatusOK, "", clients)
		return
	}

	// Method POST
	if r.Method == http.MethodPost {
		nameBytes, err := io.ReadAll(r.Body)
		if err != nil {
			serverError(w, err.Error())
			return
		}
		newClient, err := GenerateNewClient(string(nameBytes), clients)
		if err != nil {
			serverError(w, err.Error())
			return
		}

		if err := SaveConfigFile(s.configPath, append(clients, newClient)); err != nil {
			serverError(w, err.Error())
			return
		}
		makeResponse(w, http.StatusOK, "added new client", newClient)
		return
	}

	// Method DELETE
	if r.Method == http.MethodDelete {
		nameBytes, err := io.ReadAll(r.Body)
		if err != nil {
			serverError(w, err.Error())
			return
		}
		name := string(nameBytes)
		idToDelete, ok := FindClienIdtByName(name, clients)
		if !ok {
			makeResponse(w, http.StatusNotFound, "no client with name "+name, nil)
			return
		}
		clients = append(clients[:idToDelete], clients[idToDelete+1:]...)
		if SaveConfigFile(s.configPath, clients) != nil {
			serverError(w, err.Error())
			return
		}
		makeResponse(w, http.StatusOK, "client "+name+" deleted", nil)
		return
	}

	makeResponse(w, http.StatusMethodNotAllowed, "unexpected http method", nil)
}
