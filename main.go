package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

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

type ProblemDocument struct {
	ID                  int64     `json:"id"`
	ProblemStatementID  int64     `json:"problem_statement_id"`
	OriginalFileName    string    `json:"original_file_name"`
	StoredFileName      string    `json:"stored_file_name"`
	FileType            string    `json:"file_type"`
	FileSize            int64     `json:"file_size"`
	UploadedAt          time.Time `json:"uploaded_at"`
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

func isValidFileType(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	validTypes := map[string]bool{
		".pdf":  true,
		".doc":  true,
		".docx": true,
		".ppt":  true,
		".pptx": true,
	}
	return validTypes[ext]
}

func generateFileHash(content []byte) string {
	hash := sha256.Sum256(content)
	return hex.EncodeToString(hash[:])
}

func saveUploadedFile(fileContent []byte, originalName string, problemID int64) (string, error) {
	// Create uploads directory if it doesn't exist
	uploadsDir := "/app/uploads"
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create uploads directory: %v", err)
	}

	// Generate hashed filename
	hash := generateFileHash(fileContent)
	ext := filepath.Ext(originalName)
	storedFileName := fmt.Sprintf("%d_%s%s", problemID, hash[:16], ext)
	filePath := filepath.Join(uploadsDir, storedFileName)

	// Write file to disk
	if err := os.WriteFile(filePath, fileContent, 0644); err != nil {
		return "", fmt.Errorf("failed to save file: %v", err)
	}

	return storedFileName, nil
}

func initDB() error {
	connStr := "host=postgres port=5432 user=igniteuser password=ignitepass dbname=ignite sslmode=disable"
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("error opening database: %v", err)
	}

	if err = db.Ping(); err != nil {
		return fmt.Errorf("error connecting to database: %v", err)
	}

	log.Println("✅ Successfully connected to PostgreSQL database 'ignite'")
	
	// Run migrations
	if err := runMigrations(); err != nil {
		return fmt.Errorf("error running migrations: %v", err)
	}
	
	return nil
}

func runMigrations() error {
	migrations := []string{
		`CREATE TABLE IF NOT EXISTS problem_statements (
			id BIGSERIAL PRIMARY KEY,
			reference_id VARCHAR(20) UNIQUE NOT NULL,
			submitter_name VARCHAR(150) NOT NULL,
			department_name VARCHAR(200) NOT NULL,
			designation VARCHAR(150),
			contact_number VARCHAR(20),
			email VARCHAR(150) NOT NULL,
			title VARCHAR(255) NOT NULL,
			problem_description TEXT NOT NULL,
			current_challenges TEXT,
			expected_outcome TEXT,
			submission_status VARCHAR(20) NOT NULL DEFAULT 'Active',
			review_decision VARCHAR(20) NOT NULL DEFAULT 'Under Review',
			assigned_admin_id BIGINT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_problem_status ON problem_statements(submission_status)`,
		`CREATE INDEX IF NOT EXISTS idx_review_decision ON problem_statements(review_decision)`,
		`CREATE INDEX IF NOT EXISTS idx_department ON problem_statements(department_name)`,
		`CREATE INDEX IF NOT EXISTS idx_created_at ON problem_statements(created_at)`,
		`CREATE TABLE IF NOT EXISTS problem_documents (
			id BIGSERIAL PRIMARY KEY,
			problem_statement_id BIGINT NOT NULL REFERENCES problem_statements(id) ON DELETE CASCADE,
			original_file_name VARCHAR(255),
			stored_file_name VARCHAR(255),
			file_type VARCHAR(20),
			file_size BIGINT,
			uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_problem_statement_id ON problem_documents(problem_statement_id)`,
		`CREATE TABLE IF NOT EXISTS admin_users (
			id BIGSERIAL PRIMARY KEY,
			name VARCHAR(150),
			email VARCHAR(150) UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			role VARCHAR(50) DEFAULT 'ADMIN',
			is_active BOOLEAN DEFAULT TRUE,
			last_login_at TIMESTAMP,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_admin_email ON admin_users(email)`,
		`CREATE INDEX IF NOT EXISTS idx_admin_active ON admin_users(is_active)`,
	}

	for _, migration := range migrations {
		if _, err := db.Exec(migration); err != nil {
			return err
		}
	}
	
	log.Println("✅ Database migrations completed successfully")
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

	// Parse multipart form (max 10MB per file)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Failed to parse form data", http.StatusBadRequest)
		return
	}

	// Extract form fields
	submitterName := r.FormValue("submitter_name")
	departmentName := r.FormValue("department_name")
	designation := r.FormValue("designation")
	contactNumber := r.FormValue("contact_number")
	email := r.FormValue("email")
	title := r.FormValue("title")
	problemDescription := r.FormValue("problem_description")
	currentChallenges := r.FormValue("current_challenges")
	expectedOutcome := r.FormValue("expected_outcome")

	// Validate required fields
	if submitterName == "" || departmentName == "" || email == "" || 
	   title == "" || problemDescription == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Validate character limits
	if len(problemDescription) > 750 {
		http.Error(w, "Problem description exceeds 750 characters", http.StatusBadRequest)
		return
	}
	if len(currentChallenges) > 1000 {
		http.Error(w, "Current challenges exceeds 1000 characters", http.StatusBadRequest)
		return
	}
	if len(expectedOutcome) > 750 {
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
		submitterName,
		departmentName,
		designation,
		contactNumber,
		email,
		title,
		problemDescription,
		currentChallenges,
		expectedOutcome,
	).Scan(&problemStatement.ID, &problemStatement.CreatedAt)

	if err != nil {
		log.Printf("Error inserting problem statement: %v", err)
		http.Error(w, "Failed to save problem statement", http.StatusInternalServerError)
		return
	}

	problemStatement.ReferenceID = referenceID
	problemStatement.SubmitterName = submitterName
	problemStatement.DepartmentName = departmentName
	problemStatement.Email = email
	problemStatement.Title = title
	problemStatement.SubmissionStatus = "Active"
	problemStatement.ReviewDecision = "Under Review"

	// Handle file uploads
	uploadedFiles := []ProblemDocument{}
	files := r.MultipartForm.File["documents"]
	
	for _, fileHeader := range files {
		// Validate file type
		if !isValidFileType(fileHeader.Filename) {
			log.Printf("Invalid file type: %s", fileHeader.Filename)
			continue
		}

		// Open uploaded file
		file, err := fileHeader.Open()
		if err != nil {
			log.Printf("Error opening file %s: %v", fileHeader.Filename, err)
			continue
		}
		defer file.Close()

		// Read file content
		fileContent, err := io.ReadAll(file)
		if err != nil {
			log.Printf("Error reading file %s: %v", fileHeader.Filename, err)
			continue
		}

		// Save file to disk
		storedFileName, err := saveUploadedFile(fileContent, fileHeader.Filename, problemStatement.ID)
		if err != nil {
			log.Printf("Error saving file %s: %v", fileHeader.Filename, err)
			continue
		}

		// Get file extension for type
		fileType := strings.TrimPrefix(strings.ToLower(filepath.Ext(fileHeader.Filename)), ".")

		// Insert file metadata into database
		docQuery := `
			INSERT INTO problem_documents (
				problem_statement_id, original_file_name, stored_file_name, 
				file_type, file_size
			) VALUES ($1, $2, $3, $4, $5)
			RETURNING id, uploaded_at
		`

		var doc ProblemDocument
		err = db.QueryRow(
			docQuery,
			problemStatement.ID,
			fileHeader.Filename,
			storedFileName,
			fileType,
			fileHeader.Size,
		).Scan(&doc.ID, &doc.UploadedAt)

		if err != nil {
			log.Printf("Error saving file metadata for %s: %v", fileHeader.Filename, err)
			continue
		}

		doc.ProblemStatementID = problemStatement.ID
		doc.OriginalFileName = fileHeader.Filename
		doc.StoredFileName = storedFileName
		doc.FileType = fileType
		doc.FileSize = fileHeader.Size

		uploadedFiles = append(uploadedFiles, doc)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":      true,
		"message":      "Problem statement submitted successfully",
		"reference_id": referenceID,
		"data":         problemStatement,
		"files":        uploadedFiles,
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
