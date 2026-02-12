package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

var (
	uploadsDir = "./uploads"
)

// EmailConfig holds SMTP configuration
type EmailConfig struct {
	Host     string
	Port     string
	Username string
	Password string
	From     string
}

var emailConfig EmailConfig

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
	Designation        *string   `json:"designation"`
	ContactNumber      *string   `json:"contact_number"`
	Email              string    `json:"email"`
	Title              string    `json:"title"`
	ProblemDescription string    `json:"problem_description"`
	CurrentChallenges  *string   `json:"current_challenges"`
	ExpectedOutcome    *string   `json:"expected_outcome"`
	SubmissionStatus   string    `json:"submission_status"`
	ReviewDecision     string    `json:"review_decision"`
	AssignedReviewer   *string   `json:"assigned_reviewer"`
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

type AdminUser struct {
	ID          int64      `json:"id"`
	Name        string     `json:"name"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	IsActive    bool       `json:"is_active"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

type AdminRegisterRequest struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AdminLoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type AdminLoginResponse struct {
	Success bool      `json:"success"`
	Message string    `json:"message"`
	Token   string    `json:"token,omitempty"`
	Admin   AdminUser `json:"admin,omitempty"`
}

var jwtSecret = []byte("your-secret-key-change-this-in-production")

var db *sql.DB

func enableCORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Allow requests from production frontend and Vercel deployment
		origin := r.Header.Get("Origin")
		allowedOrigins := []string{
			"https://ignite.kdisc.kerala.gov.in",
			"https://www.ignite.kdisc.kerala.gov.in",
			"https://igniet.kdisc.kerala.gov.in",
			"https://www.igniet.kdisc.kerala.gov.in",
			"https://ignietkdisc.vercel.app",
			"https://www.ignietkdisc.vercel.app",
			"http://localhost:3000", // Local development
		}
		
		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				break
			}
		}
		
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next(w, r)
	}
}

type contextKey string

const (
	contextKeyAdminID    contextKey = "admin_id"
	contextKeyAdminEmail contextKey = "admin_email"
	contextKeyAdminRole  contextKey = "admin_role"
)

func authenticateAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Allow OPTIONS requests to pass through for CORS preflight
		if r.Method == "OPTIONS" {
			next(w, r)
			return
		}

		var tokenString string

		// First try to get token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			// Extract token from "Bearer <token>"
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
			if tokenString == authHeader {
				http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
				return
			}
		} else {
			// Fallback: try to get token from query parameter (for file downloads)
			tokenString = r.URL.Query().Get("token")
			if tokenString == "" {
				http.Error(w, "Authorization header required", http.StatusUnauthorized)
				return
			}
		}

		// Parse and validate token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method")
			}
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}

		// Extract claims and add to request context
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			ctx := r.Context()
			ctx = context.WithValue(ctx, contextKeyAdminID, int64(claims["admin_id"].(float64)))
			ctx = context.WithValue(ctx, contextKeyAdminEmail, claims["email"].(string))
			ctx = context.WithValue(ctx, contextKeyAdminRole, claims["role"].(string))
			r = r.WithContext(ctx)
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
	// Ensure uploads directory exists
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
	// Read database configuration from environment variables
	dbHost := os.Getenv("DB_HOST")
	if dbHost == "" {
		dbHost = "localhost"
	}
	dbPort := os.Getenv("DB_PORT")
	if dbPort == "" {
		dbPort = "5432"
	}
	dbUser := os.Getenv("DB_USER")
	if dbUser == "" {
		dbUser = "igniteuser"
	}
	dbPassword := os.Getenv("DB_PASSWORD")
	if dbPassword == "" {
		dbPassword = "ignitepass"
	}
	dbName := os.Getenv("DB_NAME")
	if dbName == "" {
		dbName = "ignite"
	}

	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		dbHost, dbPort, dbUser, dbPassword, dbName)
	
	log.Printf("📡 Connecting to PostgreSQL at %s:%s...", dbHost, dbPort)
	
	var err error
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("error opening database: %v", err)
	}

	if err = db.Ping(); err != nil {
		return fmt.Errorf("error connecting to database: %v", err)
	}

	log.Println("✅ Successfully connected to PostgreSQL database 'igniet'")
	
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
		`CREATE TABLE IF NOT EXISTS internal_remarks (
			id BIGSERIAL PRIMARY KEY,
			problem_statement_id BIGINT NOT NULL REFERENCES problem_statements(id) ON DELETE CASCADE,
			admin_id BIGINT NOT NULL REFERENCES admin_users(id),
			remark TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_internal_remarks_problem ON internal_remarks(problem_statement_id)`,
		`CREATE INDEX IF NOT EXISTS idx_internal_remarks_admin ON internal_remarks(admin_id)`,
		`CREATE TABLE IF NOT EXISTS audit_logs (
			id BIGSERIAL PRIMARY KEY,
			admin_id BIGINT NULL REFERENCES admin_users(id),
			action_type VARCHAR(100) NOT NULL,
			entity_type VARCHAR(100),
			entity_id BIGINT,
			description TEXT,
			ip_address VARCHAR(45),
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_admin ON audit_logs(admin_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action_type)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_entity ON audit_logs(entity_type, entity_id)`,
		`CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at)`,
		`CREATE TABLE IF NOT EXISTS password_reset_tokens (
			id BIGSERIAL PRIMARY KEY,
			admin_id BIGINT NOT NULL REFERENCES admin_users(id) ON DELETE CASCADE,
			token VARCHAR(255) UNIQUE NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			is_used BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_password_reset_token ON password_reset_tokens(token)`,
		`CREATE INDEX IF NOT EXISTS idx_password_reset_admin ON password_reset_tokens(admin_id)`,
		`CREATE INDEX IF NOT EXISTS idx_password_reset_expires ON password_reset_tokens(expires_at)`,
		`CREATE TABLE IF NOT EXISTS export_logs (
			id BIGSERIAL PRIMARY KEY,
			admin_id BIGINT REFERENCES admin_users(id),
			export_type VARCHAR(20),
			applied_filters JSONB,
			record_count INT,
			exported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`CREATE INDEX IF NOT EXISTS idx_export_logs_admin ON export_logs(admin_id)`,
		`CREATE INDEX IF NOT EXISTS idx_export_logs_type ON export_logs(export_type)`,
		`CREATE INDEX IF NOT EXISTS idx_export_logs_exported ON export_logs(exported_at)`,
		`CREATE TABLE IF NOT EXISTS submission_status_enum (
			id SERIAL PRIMARY KEY,
			status_name VARCHAR(50) UNIQUE NOT NULL,
			description TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT INTO submission_status_enum (status_name, description) VALUES
			('Active', 'Problem statement is currently active'),
			('PoC', 'Proof of Concept stage'),
			('Closed', 'Problem statement is closed')
		ON CONFLICT (status_name) DO NOTHING`,
		`CREATE TABLE IF NOT EXISTS review_decision_enum (
			id SERIAL PRIMARY KEY,
			decision_name VARCHAR(50) UNIQUE NOT NULL,
			description TEXT,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`INSERT INTO review_decision_enum (decision_name, description) VALUES
			('Under Review', 'Submission is under review'),
			('Accepted', 'Submission has been accepted'),
			('Rejected', 'Submission has been rejected')
		ON CONFLICT (decision_name) DO NOTHING`,
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
		Database:  "igniet",
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

	// Send acknowledgment email
	go sendAcknowledgmentEmail(problemStatement.Email, problemStatement.SubmitterName, problemStatement.ReferenceID)

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

func adminRegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AdminRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Insert admin user
	query := `
		INSERT INTO admin_users (name, email, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id, created_at
	`

	var admin AdminUser
	err = db.QueryRow(query, req.Name, req.Email, string(hashedPassword)).Scan(&admin.ID, &admin.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") {
			http.Error(w, "Email already exists", http.StatusConflict)
			return
		}
		log.Printf("Error creating admin: %v", err)
		http.Error(w, "Failed to create admin user", http.StatusInternalServerError)
		return
	}

	admin.Name = req.Name
	admin.Email = req.Email
	admin.Role = "ADMIN"
	admin.IsActive = true

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Admin user created successfully",
		"admin":   admin,
	})
}

func adminLoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req AdminLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Email == "" || req.Password == "" {
		http.Error(w, "Email and password are required", http.StatusBadRequest)
		return
	}

	// Get admin from database
	query := `
		SELECT id, name, email, password_hash, role, is_active, last_login_at, created_at
		FROM admin_users
		WHERE email = $1 AND is_active = true
	`

	var admin AdminUser
	var passwordHash string
	err := db.QueryRow(query, req.Email).Scan(
		&admin.ID, &admin.Name, &admin.Email, &passwordHash,
		&admin.Role, &admin.IsActive, &admin.LastLoginAt, &admin.CreatedAt,
	)

	if err == sql.ErrNoRows {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}
	if err != nil {
		log.Printf("Error fetching admin: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Update last login time
	updateQuery := `UPDATE admin_users SET last_login_at = $1 WHERE id = $2`
	now := time.Now()
	db.Exec(updateQuery, now, admin.ID)
	admin.LastLoginAt = &now

	// Generate JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"admin_id": admin.ID,
		"email":    admin.Email,
		"role":     admin.Role,
		"exp":      time.Now().Add(24 * time.Hour).Unix(),
	})

	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		log.Printf("Error generating token: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AdminLoginResponse{
		Success: true,
		Message: "Login successful",
		Token:   tokenString,
		Admin:   admin,
	})
}

func adminDashboardHandler(w http.ResponseWriter, r *http.Request) {
	adminID := r.Header.Get("X-Admin-ID")
	adminEmail := r.Header.Get("X-Admin-Email")

	// Get query parameters for filtering
	department := r.URL.Query().Get("department")
	startDate := r.URL.Query().Get("start_date")
	endDate := r.URL.Query().Get("end_date")

	// Get problem statements statistics
	var totalProblems, activeProblems, underReview, accepted, rejected int
	db.QueryRow("SELECT COUNT(*) FROM problem_statements").Scan(&totalProblems)
	db.QueryRow("SELECT COUNT(*) FROM problem_statements WHERE submission_status = 'Active'").Scan(&activeProblems)
	db.QueryRow("SELECT COUNT(*) FROM problem_statements WHERE review_decision = 'Under Review'").Scan(&underReview)
	db.QueryRow("SELECT COUNT(*) FROM problem_statements WHERE review_decision = 'Accepted'").Scan(&accepted)
	db.QueryRow("SELECT COUNT(*) FROM problem_statements WHERE review_decision = 'Rejected'").Scan(&rejected)

	// Build dynamic query for recent submissions
	recentQuery := `
		SELECT id, reference_id, submitter_name, department_name, title, 
		       submission_status, review_decision, created_at
		FROM problem_statements
		WHERE 1=1
	`
	args := []interface{}{}
	argCount := 0

	// Add department filter
	if department != "" {
		argCount++
		recentQuery += fmt.Sprintf(" AND LOWER(department_name) LIKE LOWER($%d)", argCount)
		args = append(args, "%"+department+"%")
	}

	// Add date range filters
	if startDate != "" {
		argCount++
		recentQuery += fmt.Sprintf(" AND created_at >= $%d", argCount)
		args = append(args, startDate)
	}
	if endDate != "" {
		argCount++
		recentQuery += fmt.Sprintf(" AND created_at <= $%d || ' 23:59:59'", argCount)
		args = append(args, endDate)
	}

	recentQuery += " ORDER BY created_at DESC LIMIT 50"

	rows, err := db.Query(recentQuery, args...)
	if err != nil {
		log.Printf("Error fetching recent submissions: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	recentSubmissions := []ProblemStatement{}
	for rows.Next() {
		var ps ProblemStatement
		err := rows.Scan(
			&ps.ID, &ps.ReferenceID, &ps.SubmitterName, &ps.DepartmentName,
			&ps.Title, &ps.SubmissionStatus, &ps.ReviewDecision, &ps.CreatedAt,
		)
		if err != nil {
			log.Printf("Error scanning row: %v", err)
			continue
		}
		recentSubmissions = append(recentSubmissions, ps)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"admin": map[string]string{
			"id":    adminID,
			"email": adminEmail,
		},
		"statistics": map[string]int{
			"total_problems":   totalProblems,
			"active_problems":  activeProblems,
			"under_review":     underReview,
			"accepted":         accepted,
			"rejected":         rejected,
		},
		"recent_submissions": recentSubmissions,
	})
}

func listProblemStatementsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get pagination parameters
	page := 1
	limit := 10
	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if p, err := fmt.Sscanf(pageStr, "%d", &page); err == nil && p == 1 && page > 0 {
			// page is valid
		} else {
			page = 1
		}
	}
	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if l, err := fmt.Sscanf(limitStr, "%d", &limit); err == nil && l == 1 && limit > 0 && limit <= 100 {
			// limit is valid
		} else {
			limit = 10
		}
	}

	offset := (page - 1) * limit

	// Get total count
	var totalCount int
	err := db.QueryRow("SELECT COUNT(*) FROM problem_statements").Scan(&totalCount)
	if err != nil {
		log.Printf("Error counting problem statements: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Get paginated problem statements
	query := `
		SELECT id, reference_id, submitter_name, department_name, designation,
		       contact_number, email, title, problem_description, current_challenges,
		       expected_outcome, submission_status, review_decision, assigned_reviewer, created_at
		FROM problem_statements
		ORDER BY created_at DESC
		LIMIT $1 OFFSET $2
	`

	rows, err := db.Query(query, limit, offset)
	if err != nil {
		log.Printf("Error fetching problem statements: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	problemStatements := []ProblemStatement{}
	for rows.Next() {
		var ps ProblemStatement
		err := rows.Scan(
			&ps.ID, &ps.ReferenceID, &ps.SubmitterName, &ps.DepartmentName,
			&ps.Designation, &ps.ContactNumber, &ps.Email, &ps.Title,
			&ps.ProblemDescription, &ps.CurrentChallenges, &ps.ExpectedOutcome,
			&ps.SubmissionStatus, &ps.ReviewDecision, &ps.AssignedReviewer, &ps.CreatedAt,
		)
		if err != nil {
			log.Printf("Error scanning problem statement: %v", err)
			continue
		}
		problemStatements = append(problemStatements, ps)
	}

	totalPages := (totalCount + limit - 1) / limit

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":            true,
		"problem_statements": problemStatements,
		"pagination": map[string]int{
			"page":        page,
			"limit":       limit,
			"total_count": totalCount,
			"total_pages": totalPages,
		},
	})
}

func getProblemStatementHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get ID from query parameter
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Missing id parameter", http.StatusBadRequest)
		return
	}

	var id int64
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
		http.Error(w, "Invalid id parameter", http.StatusBadRequest)
		return
	}

	// Fetch problem statement
	query := `
		SELECT id, reference_id, submitter_name, department_name, designation,
		       contact_number, email, title, problem_description, current_challenges,
		       expected_outcome, submission_status, review_decision, assigned_reviewer, created_at
		FROM problem_statements
		WHERE id = $1
	`

	var ps ProblemStatement
	err := db.QueryRow(query, id).Scan(
		&ps.ID, &ps.ReferenceID, &ps.SubmitterName, &ps.DepartmentName,
		&ps.Designation, &ps.ContactNumber, &ps.Email, &ps.Title,
		&ps.ProblemDescription, &ps.CurrentChallenges, &ps.ExpectedOutcome,
		&ps.SubmissionStatus, &ps.ReviewDecision, &ps.AssignedReviewer, &ps.CreatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Problem statement not found", http.StatusNotFound)
			return
		}
		log.Printf("Error fetching problem statement: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":           true,
		"problem_statement": ps,
	})
}

func getProblemDocumentsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get problem statement ID from query parameter
	idStr := r.URL.Query().Get("problem_id")
	if idStr == "" {
		http.Error(w, "Missing problem_id parameter", http.StatusBadRequest)
		return
	}

	var problemID int64
	if _, err := fmt.Sscanf(idStr, "%d", &problemID); err != nil {
		http.Error(w, "Invalid problem_id parameter", http.StatusBadRequest)
		return
	}

	// Fetch documents for this problem statement
	query := `
		SELECT id, problem_statement_id, original_file_name, stored_file_name,
		       file_type, file_size, uploaded_at
		FROM problem_documents
		WHERE problem_statement_id = $1
		ORDER BY uploaded_at DESC
	`

	rows, err := db.Query(query, problemID)
	if err != nil {
		log.Printf("Error fetching problem documents: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	documents := []ProblemDocument{}
	for rows.Next() {
		var doc ProblemDocument
		err := rows.Scan(
			&doc.ID, &doc.ProblemStatementID, &doc.OriginalFileName,
			&doc.StoredFileName, &doc.FileType, &doc.FileSize, &doc.UploadedAt,
		)
		if err != nil {
			log.Printf("Error scanning document: %v", err)
			continue
		}
		documents = append(documents, doc)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"documents": documents,
	})
}

func downloadDocumentHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Authenticate using token from query parameter or header
	tokenString := r.URL.Query().Get("token")
	if tokenString == "" {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			tokenString = strings.TrimPrefix(authHeader, "Bearer ")
		}
	}

	if tokenString == "" {
		http.Error(w, "Authorization header required", http.StatusUnauthorized)
		return
	}

	// Parse and validate token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
		return
	}

	// Get document ID from query parameter
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "Missing id parameter", http.StatusBadRequest)
		return
	}

	var docID int64
	if _, err := fmt.Sscanf(idStr, "%d", &docID); err != nil {
		http.Error(w, "Invalid id parameter", http.StatusBadRequest)
		return
	}

	// Fetch document info from database
	var storedFileName, originalFileName, fileType string
	query := `SELECT stored_file_name, original_file_name, file_type FROM problem_documents WHERE id = $1`
	err = db.QueryRow(query, docID).Scan(&storedFileName, &originalFileName, &fileType)
	if err != nil {
		if err == sql.ErrNoRows {
			http.Error(w, "Document not found", http.StatusNotFound)
			return
		}
		log.Printf("Error fetching document: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Construct file path
	filePath := filepath.Join(uploadsDir, storedFileName)

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "File not found on disk", http.StatusNotFound)
		return
	}

	// Set headers for file download/display
	w.Header().Set("Content-Type", fileType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s\"", originalFileName))

	// Serve the file
	http.ServeFile(w, r, filePath)
}

func serveUploadedFileHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get filename from URL path
	filename := r.URL.Path[len("/uploads/"):]
	if filename == "" {
		http.Error(w, "Missing filename", http.StatusBadRequest)
		return
	}

	// Construct file path
	filePath := filepath.Join("/app/uploads", filename)

	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Serve the file
	http.ServeFile(w, r, filePath)
}

func updateReviewDecisionHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID             int64  `json:"id"`
		ReviewDecision string `json:"review_decision"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate review decision
	validDecisions := map[string]bool{
		"Under Review": true,
		"Accepted":     true,
		"Rejected":     true,
	}

	if !validDecisions[req.ReviewDecision] {
		http.Error(w, "Invalid review decision", http.StatusBadRequest)
		return
	}

	// Update in database
	query := `UPDATE problem_statements SET review_decision = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`
	result, err := db.Exec(query, req.ReviewDecision, req.ID)
	if err != nil {
		log.Printf("Error updating review decision: %v", err)
		http.Error(w, "Failed to update review decision", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Problem statement not found", http.StatusNotFound)
		return
	}

	// Log audit action
	adminEmail := r.Context().Value(contextKeyAdminEmail).(string)
	adminID := r.Context().Value(contextKeyAdminID).(int64)
	details := fmt.Sprintf("Changed review decision to: %s", req.ReviewDecision)
	go logAuditAction(adminID, adminEmail, "UPDATE_REVIEW_DECISION", "problem_statement", req.ID, details)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Review decision updated successfully",
	})
}

func updateSubmissionStatusHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID               int64  `json:"id"`
		SubmissionStatus string `json:"submission_status"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate submission status
	validStatuses := map[string]bool{
		"Active": true,
		"PoC":    true,
		"Closed": true,
	}

	if !validStatuses[req.SubmissionStatus] {
		http.Error(w, "Invalid submission status", http.StatusBadRequest)
		return
	}

	// Update in database
	query := `UPDATE problem_statements SET submission_status = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`
	result, err := db.Exec(query, req.SubmissionStatus, req.ID)
	if err != nil {
		log.Printf("Error updating submission status: %v", err)
		http.Error(w, "Failed to update submission status", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Problem statement not found", http.StatusNotFound)
		return
	}

	// Log audit action
	adminEmail := r.Context().Value(contextKeyAdminEmail).(string)
	adminID := r.Context().Value(contextKeyAdminID).(int64)
	details := fmt.Sprintf("Changed submission status to: %s", req.SubmissionStatus)
	go logAuditAction(adminID, adminEmail, "UPDATE_SUBMISSION_STATUS", "problem_statement", req.ID, details)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Submission status updated successfully",
	})
}

func getInternalRemarksHandler(w http.ResponseWriter, r *http.Request) {
	problemIDStr := r.URL.Query().Get("problem_id")
	if problemIDStr == "" {
		http.Error(w, "problem_id is required", http.StatusBadRequest)
		return
	}

	problemID, err := strconv.ParseInt(problemIDStr, 10, 64)
	if err != nil {
		http.Error(w, "Invalid problem_id", http.StatusBadRequest)
		return
	}

	query := `
		SELECT ir.id, ir.problem_statement_id, ir.remark, au.email, ir.created_at, ir.updated_at
		FROM internal_remarks ir
		LEFT JOIN admin_users au ON ir.admin_id = au.id
		WHERE ir.problem_statement_id = $1
		ORDER BY ir.created_at DESC
	`

	rows, err := db.Query(query, problemID)
	if err != nil {
		log.Printf("Error fetching internal remarks: %v", err)
		http.Error(w, "Failed to fetch internal remarks", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var remarks []map[string]interface{}
	for rows.Next() {
		var id, problemStatementID int64
		var remarkText, createdBy string
		var createdAt time.Time
		var updatedAt *time.Time

		if err := rows.Scan(&id, &problemStatementID, &remarkText, &createdBy, &createdAt, &updatedAt); err != nil {
			log.Printf("Error scanning remark: %v", err)
			continue
		}

		remark := map[string]interface{}{
			"id":                     id,
			"problem_statement_id":   problemStatementID,
			"remark_text":            remarkText,
			"created_by":             createdBy,
			"created_at":             createdAt,
		}
		if updatedAt != nil {
			remark["updated_at"] = *updatedAt
		}
		remarks = append(remarks, remark)
	}

	if remarks == nil {
		remarks = []map[string]interface{}{}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"remarks": remarks,
	})
}

func addInternalRemarkHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get admin ID from context
	adminID := r.Context().Value(contextKeyAdminID).(int64)

	var req struct {
		ProblemStatementID int64  `json:"problem_statement_id"`
		RemarkText         string `json:"remark_text"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.RemarkText == "" {
		http.Error(w, "remark_text is required", http.StatusBadRequest)
		return
	}

	query := `
		INSERT INTO internal_remarks (problem_statement_id, admin_id, remark, created_at)
		VALUES ($1, $2, $3, CURRENT_TIMESTAMP)
		RETURNING id
	`

	var remarkID int64
	err := db.QueryRow(query, req.ProblemStatementID, adminID, req.RemarkText).Scan(&remarkID)
	if err != nil {
		log.Printf("Error adding internal remark: %v", err)
		http.Error(w, "Failed to add internal remark", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":   true,
		"remark_id": remarkID,
		"message":   "Internal remark added successfully",
	})
}

func deleteInternalRemarkHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID int64 `json:"id"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	query := `DELETE FROM internal_remarks WHERE id = $1`
	result, err := db.Exec(query, req.ID)
	if err != nil {
		log.Printf("Error deleting internal remark: %v", err)
		http.Error(w, "Failed to delete internal remark", http.StatusInternalServerError)
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		http.Error(w, "Remark not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Internal remark deleted successfully",
	})
}

func exportProblemsCSVHandler(w http.ResponseWriter, r *http.Request) {
	// Get admin info from context for audit logging
	adminID := r.Context().Value("adminID")
	adminEmail := r.Context().Value("adminEmail")
	
	// Log the export action to export_logs table
	if adminID != nil {
		_, err := db.Exec(
			`INSERT INTO export_logs (admin_id, export_type, record_count, exported_at) VALUES ($1, $2, 0, CURRENT_TIMESTAMP)`,
			adminID.(int64), "CSV",
		)
		if err != nil {
			log.Printf("Error logging export: %v", err)
		}
		
		// Also log to audit_logs
		logAuditAction(adminID.(int64), adminEmail.(string), "EXPORT_CSV", "problem_statements", 0, "Exported all problem statements to CSV")
	}

	query := `
		SELECT id, reference_id, submitter_name, department_name, designation, contact_number, email,
		       title, problem_description, submission_status, review_decision, created_at
		FROM problem_statements
		ORDER BY created_at DESC
	`

	rows, err := db.Query(query)
	if err != nil {
		log.Printf("Error fetching problems for export: %v", err)
		http.Error(w, "Failed to export problems", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=problem_statements.csv")

	// Write CSV header
	fmt.Fprintf(w, "Reference ID,Submitter Name,Department,Designation,Contact,Email,Title,Description,Status,Decision,Created At\n")

	// Write CSV rows
	for rows.Next() {
		var id int64
		var refID, submitterName, deptName, designation, contact, email, title, desc, status, decision string
		var createdAt time.Time

		if err := rows.Scan(&id, &refID, &submitterName, &deptName, &designation, &contact, &email, &title, &desc, &status, &decision, &createdAt); err != nil {
			log.Printf("Error scanning row: %v", err)
			continue
		}

		// Escape quotes in CSV fields
		escapeCSV := func(s string) string {
			return "\"" + s + "\""
		}

		fmt.Fprintf(w, "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n",
			escapeCSV(refID),
			escapeCSV(submitterName),
			escapeCSV(deptName),
			escapeCSV(designation),
			escapeCSV(contact),
			escapeCSV(email),
			escapeCSV(title),
			escapeCSV(desc),
			escapeCSV(status),
			escapeCSV(decision),
			escapeCSV(createdAt.Format("2006-01-02 15:04:05")),
		)
	}
}

func assignToReviewerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		ID               int64  `json:"id"`
		AssignedReviewer string `json:"assigned_reviewer"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Invalid request body",
		})
		return
	}

	// Validate ID
	if req.ID <= 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Invalid problem statement ID",
		})
		return
	}

	// Trim whitespace from reviewer
	req.AssignedReviewer = strings.TrimSpace(req.AssignedReviewer)

	// Update assignment in database
	query := `UPDATE problem_statements SET assigned_reviewer = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2`
	result, err := db.Exec(query, req.AssignedReviewer, req.ID)
	if err != nil {
		log.Printf("Error assigning reviewer: %v", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Failed to assign reviewer",
		})
		return
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": "Problem statement not found",
		})
		return
	}

	// Log audit action
	adminEmail := r.Context().Value(contextKeyAdminEmail).(string)
	adminID := r.Context().Value(contextKeyAdminID).(int64)
	details := fmt.Sprintf("Assigned to reviewer: %s", req.AssignedReviewer)
	go logAuditAction(adminID, adminEmail, "ASSIGN_REVIEWER", "problem_statement", req.ID, details)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success":           true,
		"message":           "Reviewer assigned successfully",
		"assigned_reviewer": req.AssignedReviewer,
	})
}

func requestPasswordResetHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Check if user exists
	var userID int64
	err := db.QueryRow("SELECT id FROM admin_users WHERE email = $1", req.Email).Scan(&userID)
	if err != nil {
		// Don't reveal if email exists or not for security
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": true,
			"message": "If the email exists, a reset link will be sent",
		})
		return
	}

	// Generate reset token
	token := fmt.Sprintf("%x", time.Now().UnixNano())
	expiresAt := time.Now().Add(24 * time.Hour)

	// Store token in database
	query := `INSERT INTO password_reset_tokens (admin_id, token, expires_at, created_at) VALUES ($1, $2, $3, CURRENT_TIMESTAMP)`
	_, err = db.Exec(query, userID, token, expiresAt)
	if err != nil {
		log.Printf("Error storing reset token: %v", err)
		http.Error(w, "Failed to process request", http.StatusInternalServerError)
		return
	}

	// Send password reset email
	go sendPasswordResetEmail(req.Email, token)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "If the email exists, a reset link will be sent",
	})
}

func resetPasswordHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Verify token
	var adminUserID int64
	var expiresAt time.Time
	var isUsed bool

	query := `SELECT admin_id, expires_at, is_used FROM password_reset_tokens WHERE token = $1`
	err := db.QueryRow(query, req.Token).Scan(&adminUserID, &expiresAt, &isUsed)
	if err != nil {
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	if isUsed || time.Now().After(expiresAt) {
		http.Error(w, "Invalid or expired token", http.StatusBadRequest)
		return
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to process password", http.StatusInternalServerError)
		return
	}

	// Update password
	_, err = db.Exec("UPDATE admin_users SET password_hash = $1 WHERE id = $2", string(hashedPassword), adminUserID)
	if err != nil {
		log.Printf("Error updating password: %v", err)
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	// Mark token as used
	_, err = db.Exec("UPDATE password_reset_tokens SET is_used = TRUE WHERE token = $1", req.Token)
	if err != nil {
		log.Printf("Error marking token as used: %v", err)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"success": true,
		"message": "Password reset successfully",
	})
}

func sendAcknowledgmentEmail(email, name, referenceID string) {
    subject := "Problem Statement Submission Confirmation - IGNIET"
    body := fmt.Sprintf(`Dear %s,

Thank you for submitting your problem statement to IGNIET.

Your submission has been received successfully with the following reference ID: %s

Our team will review your submission and get back to you within 5-7 business days.

You can track the status of your submission by contacting our team with the reference ID.

For any queries, please contact us:
Email: ignietkdisc@gmail.com
Contact Number: +91 98950 26721

Best regards,
IGNIET Team`, name, referenceID)

    err := sendEmail(email, subject, body)
    if err != nil {
        log.Printf("Error sending acknowledgment email to %s: %v", email, err)
    } else {
        log.Printf("Acknowledgment email sent successfully to %s (Ref: %s)", email, referenceID)
    }
}

// sendPasswordResetEmail sends a password reset email with reset link
func sendPasswordResetEmail(email, token string) error {
	subject := "Password Reset Request - IGNIET Admin"
	
	// Construct reset link - use environment variable or default to localhost
	frontendURL := os.Getenv("FRONTEND_URL")
	if frontendURL == "" {
		frontendURL = "http://localhost:3000"
	}
	resetLink := fmt.Sprintf("%s/admin/reset-password?token=%s", frontendURL, token)
	
	body := fmt.Sprintf(`Dear Admin,

We received a request to reset your password for your IGNIET admin account.

To reset your password, please click on the following link:
%s

This link will expire in 24 hours.

If you did not request a password reset, please ignore this email and your password will remain unchanged.

Best regards,
IGNIET Team`, resetLink)
	
	err := sendEmail(email, subject, body)
	if err != nil {
		log.Printf("Error sending password reset email to %s: %v", email, err)
		return err
	}
	
	log.Printf("Password reset email sent successfully to %s", email)
	return nil
}

// sendEmail sends an email using SMTP
func sendEmail(to, subject, body string) error {
	if emailConfig.Host == "" || emailConfig.Port == "" {
		log.Println("Email configuration not set, skipping email send")
		return fmt.Errorf("email not configured")
	}

	from := emailConfig.From
	auth := smtp.PlainAuth("", emailConfig.Username, emailConfig.Password, emailConfig.Host)

	msg := []byte(fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"\r\n"+
		"%s\r\n", from, to, subject, body))

	addr := fmt.Sprintf("%s:%s", emailConfig.Host, emailConfig.Port)
	err := smtp.SendMail(addr, auth, from, []string{to}, msg)
	if err != nil {
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}

func logAuditAction(adminUserID int64, adminEmail, action, entityType string, entityID int64, details string) {
	query := `
		INSERT INTO audit_logs (admin_id, action_type, entity_type, entity_id, description, created_at)
		VALUES ($1, $2, $3, $4, $5, CURRENT_TIMESTAMP)
	`
	// Combine admin email and details for description
	description := fmt.Sprintf("[%s] %s", adminEmail, details)
	_, err := db.Exec(query, adminUserID, action, entityType, entityID, description)
	if err != nil {
		log.Printf("Error logging audit action: %v", err)
	}
}

func main() {
	// Load environment variables from .env file ONLY if not already set
	// In production, systemd provides env vars via EnvironmentFile - don't override them
	if os.Getenv("DB_HOST") == "" {
		// Not in systemd environment, try loading .env file for local dev
		if err := godotenv.Load(".env"); err != nil {
			log.Println("⚠️  No .env file found, using system environment variables")
		} else {
			log.Println("✅ Loaded environment variables from .env file")
		}
	} else {
		log.Println("✅ Using environment variables from systemd")
	}

	// Create uploads directory if it doesn't exist
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		log.Printf("⚠️  Warning: Could not create uploads directory: %v", err)
	} else {
		log.Printf("✅ Uploads directory ready: %s", uploadsDir)
	}

	// Load email configuration
	emailConfig = EmailConfig{
		Host:     os.Getenv("SMTP_HOST"),
		Port:     os.Getenv("SMTP_PORT"),
		Username: os.Getenv("SMTP_USERNAME"),
		Password: os.Getenv("SMTP_PASSWORD"),
		From:     os.Getenv("SMTP_FROM"),
	}
	
	if emailConfig.Host != "" {
		log.Printf("✅ Email configuration loaded (SMTP: %s:%s)", emailConfig.Host, emailConfig.Port)
	} else {
		log.Println("⚠️  Email configuration not set - emails will not be sent")
	}

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
	mux.HandleFunc("/api/admin/register", enableCORS(adminRegisterHandler))
	mux.HandleFunc("/api/admin/login", enableCORS(adminLoginHandler))
	mux.HandleFunc("/api/admin/dashboard", enableCORS(authenticateAdmin(adminDashboardHandler)))
	mux.HandleFunc("/api/admin/problem-statements", enableCORS(authenticateAdmin(listProblemStatementsHandler)))
	mux.HandleFunc("/api/admin/problem-statement", enableCORS(authenticateAdmin(getProblemStatementHandler)))
	mux.HandleFunc("/api/admin/problem-documents", enableCORS(authenticateAdmin(getProblemDocumentsHandler)))
	mux.HandleFunc("/api/admin/download-document", enableCORS(downloadDocumentHandler))
	mux.HandleFunc("/api/admin/update-review-decision", enableCORS(authenticateAdmin(updateReviewDecisionHandler)))
	mux.HandleFunc("/api/admin/update-submission-status", enableCORS(authenticateAdmin(updateSubmissionStatusHandler)))
	mux.HandleFunc("/api/admin/internal-remarks", enableCORS(authenticateAdmin(getInternalRemarksHandler)))
	mux.HandleFunc("/api/admin/add-internal-remark", enableCORS(authenticateAdmin(addInternalRemarkHandler)))
	mux.HandleFunc("/api/admin/delete-internal-remark", enableCORS(authenticateAdmin(deleteInternalRemarkHandler)))
	mux.HandleFunc("/api/admin/export-csv", enableCORS(authenticateAdmin(exportProblemsCSVHandler)))
	mux.HandleFunc("/api/admin/assign-reviewer", enableCORS(authenticateAdmin(assignToReviewerHandler)))
	mux.HandleFunc("/api/auth/request-password-reset", enableCORS(requestPasswordResetHandler))
	mux.HandleFunc("/api/auth/reset-password", enableCORS(resetPasswordHandler))
	mux.HandleFunc("/uploads/", enableCORS(serveUploadedFileHandler))
	
	port := ":8080"
	fmt.Printf("🚀 Server starting on http://localhost%s\n", port)
	fmt.Println("📍 Endpoints:")
	fmt.Println("   GET  /        - Hello endpoint")
	fmt.Println("   GET  /health  - Health check")
	fmt.Println("   POST /api/problem-statements - Submit problem statement")
	fmt.Println("   POST /api/admin/register - Admin registration")
	fmt.Println("   POST /api/admin/login - Admin login")
	fmt.Println("   GET  /api/admin/dashboard - Admin dashboard (protected)")
	fmt.Println("🗄️  Database: igniet (PostgreSQL)")
	
	if err := http.ListenAndServe(port, mux); err != nil {
		log.Fatal(err)
	}
}
