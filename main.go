package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

type Response struct {
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := Response{
		Message:   "Server is healthy",
		Timestamp: time.Now(),
		Status:    "ok",
	}
	json.NewEncoder(w).Encode(response)
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := Response{
		Message:   "Hello from Go web server!",
		Timestamp: time.Now(),
		Status:    "success",
	}
	json.NewEncoder(w).Encode(response)
}

func main() {
	mux := http.NewServeMux()
	
	mux.HandleFunc("/", helloHandler)
	mux.HandleFunc("/health", healthHandler)
	
	port := ":5000"
	fmt.Printf("🚀 Server starting on http://localhost%s\n", port)
	fmt.Println("📍 Endpoints:")
	fmt.Println("   GET /        - Hello endpoint")
	fmt.Println("   GET /health  - Health check")
	
	if err := http.ListenAndServe(port, mux); err != nil {
		log.Fatal(err)
	}
}
