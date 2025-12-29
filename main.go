package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
	"strconv"
	"strings"

	_ "github.com/lib/pq"
)

type Response struct {
	Message   string    `json:"message"`
	Timestamp time.Time `json:"timestamp"`
	Status    string    `json:"status"`
}

type DBStatus struct {
	Connected bool   `json:"connected"`
	Database  string `json:"database"`
	Message   string `json:"message"`
}

type ProblemStatement struct {
	ID                 int64     `json:"id"`
	ReferenceID        string    `json:"reference_id"`
	SubmitterName      string    `json:"submitter_name"`
	DepartmentName     string    `json:"department_name"`
	Designation        string    `json:"designation"`
	ContactNumber      string    `json:"contact_number"`
	Email              string    `json:"email"`
	Title              string    `json:"title"`
	ProblemDescription string    `json:"problem_description"`
	CurrentChallenges  string    `json:"current_challenges"`
	ExpectedOutcome    string    `json:"expected_outcome"`
	SubmissionStatus   string    `json:"submission_status"`
	ReviewDecision     string    `json:"review_decision"`
	CreatedAt          time.Time `json:"created_at"`
}

type ProblemStatementRequest struct {
	SubmitterName      string `json:"submitter_name"`
	DepartmentName     string `json:"department_name"`
	Designation        string `json:"designation"`
	ContactNumber      string `json:"contact_number"`
	Email              string `json:"email"`
	Title              string `json:"title"`
	ProblemDescription string `json:"problem_description"`
	CurrentChallenges  string `json:"current_challenges"`
	ExpectedOutcome    string `json:"expected_outcome"`
}

var db *sql.DB

func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next(w, r)
	}
}

func generateReferenceID() (string, error) {
	year := time.Now().Year()
	
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM problem_statements WHERE reference_id LIKE $1", 
		fmt.Sprintf("IGNIET-%d-%%", year)).Scan(&count)
	if err != nil {
		return "", err
	}
	
	nextNum := count + 1
	referenceID := fmt.Sprintf("IGNIET-%d-%06d", year, nextNum)
	return referenceID, nil
}

func initDB() error {
	connStr := "host=localhost port=5432 user=postgres dbname=ignite sslmode=disable"
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("error opening database: %v", err)
	}

	if err = db.Ping(); err != nil {
		return fmt.Errorf("error connecting to database: %v", err)
	}

	log.Println("✅ Successfully connected to PostgreSQL database 'ignite'")
	return nil
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	
	dbStatus := DBStatus{
		Connected: false,
		Database:  "ignite",
		Message:   "Database connection failed",
	}
	
	if db != nil {
		if err := db.Ping(); err == nil {
			dbStatus.Connected = true
			dbStatus.Message = "Database connection healthy"
		}
	}
	
	response := map[string]interface{}{
		"message":   "Server is healthy",
		"timestamp": time.Now(),
		"status":    "ok",
		"database":  dbStatus,
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
