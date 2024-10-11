package main

import (
	"fmt"
	"net/http"

	// "github.com/cheildo/jwt-auth-golang/login"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

func main() {
	// Initialize the database connection
	login.InitDB()

	router := mux.NewRouter()

	// Authentication routes
	router.HandleFunc("/login", login.LoginHandler).Methods("POST")
	router.HandleFunc("/register", login.RegisterHandler).Methods("POST")

	// CRUD routes for mahasiswa with JWT validation
	router.Handle("/mahasiswa", login.TokenValidationMiddleware(http.HandlerFunc(login.CreateMahasiswa))).Methods("POST")
	router.Handle("/mahasiswa", login.TokenValidationMiddleware(http.HandlerFunc(login.GetMahasiswa))).Methods("GET")
	router.Handle("/mahasiswa", login.TokenValidationMiddleware(http.HandlerFunc(login.UpdateMahasiswa))).Methods("PUT")
	router.Handle("/mahasiswa", login.TokenValidationMiddleware(http.HandlerFunc(login.DeleteMahasiswa))).Methods("DELETE")

	// Protected route
	router.HandleFunc("/protected", login.ProtectedHandler).Methods("GET")

	// Configure CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"http://localhost:3000"}, // Change this to the origin of your frontend
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	})

	// Wrap the router with the CORS middleware
	handler := c.Handler(router)

	fmt.Println("Starting the server on localhost:4000")
	err := http.ListenAndServe("localhost:4000", handler)
	if err != nil {
		fmt.Println("Could not start the server", err)
	}
}
