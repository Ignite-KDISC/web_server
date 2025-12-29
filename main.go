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
	connStr := "host=/var/run/postgresql port=5433 user=postgres dbname=ignite sslmode=disable"
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

func createProblemStatementHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req ProblemStatementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.SubmitterName == "" || req.DepartmentName == "" || req.Email == "" || 
	   req.Title == "" || req.ProblemDescription == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Validate character limits
	if len(req.ProblemDescription) > 750 {
		http.Error(w, "Problem description exceeds 750 characters", http.StatusBadRequest)
		return
	}
	if len(req.CurrentChallenges) > 1000 {
		http.Error(w, "Current challenges exceeds 1000 characters", http.StatusBadRequest)
		return
	}
	if len(req.ExpectedOutcome) > 750 {
		http.Error(w, "Expected outcome exceeds 750 characters", http.StatusBadRequest)
		return
	}

	// Generate reference ID
	referenceID, err := generateReferenceID()
	if err != nil {
		log.Printf("Error generating reference ID: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Insert into database
	query := `
		INSERT INTO problem_statements (
			reference_id, submitter_name, department_name, designation, 
			contact_number, email, title, problem_description, 
			current_challenges, expected_outcome
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, created_at
	`

	var problemStatement ProblemStatement
	err = db.QueryRow(
		query,
		referenceID,
		req.SubmitterName,
		req.DepartmentName,
		req.Designation,
		req.ContactNumber,
		req.Email,
		req.Title,
		req.ProblemDescription,
		req.CurrentChallenges,
		req.ExpectedOutcome,
	).Scan(&problemStatement.ID, &problemStatement.CreatedAt)

	if err != nil {
		log.Printf("Error inserting problem statement: %v", err)
		http.Error(w, "Failed to save problem statement", http.StatusInternalServerError)
		return
	}

	problemStatement.ReferenceID = referenceID
	problemStatement.SubmitterName = req.SubmitterName
	problemStatement.DepartmentName = req.DepartmentName
	problemStatement.Email = req.Email
	problemStatement.Title = req.Title
	problemStatement.SubmissionStatus = "Active"
	problemStatement.ReviewDecision = "Under Review"

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"message":      "Problem statement submitted successfully",
		"reference_id": referenceID,
		"data":         problemStatement,
	})
}

func main() {
	// Initialize database connection
	if err := initDB(); err != nil {
		log.Printf("⚠️  Warning: %v", err)
		log.Println("Server will start without database connection")
	}
	defer func() {
		if db != nil {
			db.Close()
		}
	}()
	
	mux := http.NewServeMux()
	
	mux.HandleFunc("/", enableCORS(helloHandler))
	mux.HandleFunc("/health", enableCORS(healthHandler))
	mux.HandleFunc("/api/problem-statements", enableCORS(createProblemStatementHandler))
	
	port := ":5000"
	fmt.Printf("🚀 Server starting on http://localhost%s\n", port)
	fmt.Println("📍 Endpoints:")
	fmt.Println("   GET  /        - Hello endpoint")
	fmt.Println("   GET  /health  - Health check")
	fmt.Println("   POST /api/problem-statements - Submit problem statement")
	fmt.Println("🗄️  Database: ignite (PostgreSQL)")
	
	if err := http.ListenAndServe(port, mux); err != nil {
		log.Fatal(err)
	}
}
