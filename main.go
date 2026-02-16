package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
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
			"https://igniet.kdisc.kerala.gov.in",
			"https://www.igniet.kdisc.kerala.gov.in",
			"https://ignietkdisc.vercel.app",
			"https://www.ignietkdisc.vercel.app",
			"https://103.119.178.148", // Direct IP access
			"http://localhost:3000", // Local development
		}
		
		// Set CORS headers for all requests
		originAllowed := false
		for _, allowedOrigin := range allowedOrigins {
			if origin == allowedOrigin {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				originAllowed = true
				break
			}
		}
		
		// If no specific origin matched but we have an origin, reject
		if !originAllowed && origin != "" {
			// Still set basic headers but don't allow origin
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Access-Control-Request-Private-Network")
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		
		// Always set these headers for Private Network Access compliance
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, Access-Control-Request-Private-Network")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400") // Cache preflight for 24 hours
		
		// Critical: Set Private Network Access header on ALL responses
		if r.Header.Get("Access-Control-Request-Private-Network") == "true" || originAllowed {
			w.Header().Set("Access-Control-Allow-Private-Network", "true")
		}
		
		// Handle preflight OPTIONS request
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		
		next(w, r)
	}
}

// securityHeadersMiddleware sets security headers on all responses (Vulnerabilities #5 Clickjacking, #7 Security Headers).
func securityHeadersMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

// rateLimitEntry tracks request count within a time window for an IP.
type rateLimitEntry struct {
	count       int
	windowStart time.Time
}

var (
	rateLimitMu   sync.Mutex
	rateLimitMap  = make(map[string]*rateLimitEntry)
	rateLimitClean time.Time
)

const (
	rateLimitWindow     = time.Minute
	rateLimitMaxLogin   = 5
	rateLimitMaxReset   = 3
	rateLimitResetWindow = 15 * time.Minute
)

func rateLimitCleanup() {
	rateLimitMu.Lock()
	defer rateLimitMu.Unlock()
	if time.Since(rateLimitClean) < 5*time.Minute {
		return
	}
	rateLimitClean = time.Now()
	for k, v := range rateLimitMap {
		if time.Since(v.windowStart) > rateLimitResetWindow {
			delete(rateLimitMap, k)
		}
	}
}

// rateLimitLogin allows rateLimitMaxLogin requests per rateLimitWindow per IP (Vulnerability #8).
func rateLimitLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if f := r.Header.Get("X-Forwarded-For"); f != "" {
			ip = strings.TrimSpace(strings.Split(f, ",")[0])
		}
		// Run cleanup without holding lock to avoid deadlock (cleanup locks internally)
		rateLimitCleanup()
		rateLimitMu.Lock()
		e, ok := rateLimitMap["login:"+ip]
		if !ok {
			e = &rateLimitEntry{count: 0, windowStart: time.Now()}
			rateLimitMap["login:"+ip] = e
		}
		if time.Since(e.windowStart) > rateLimitWindow {
			e.count = 0
			e.windowStart = time.Now()
		}
		e.count++
		if e.count > rateLimitMaxLogin {
			rateLimitMu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": "Too many login attempts. Please try again later.",
			})
			return
		}
		rateLimitMu.Unlock()
		next(w, r)
	}
}

// rateLimitPasswordReset allows rateLimitMaxReset requests per rateLimitResetWindow per IP (Vulnerability #6).
func rateLimitPasswordReset(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := r.RemoteAddr
		if f := r.Header.Get("X-Forwarded-For"); f != "" {
			ip = strings.TrimSpace(strings.Split(f, ",")[0])
		}
		// Run cleanup without holding lock to avoid deadlock (cleanup locks internally)
		rateLimitCleanup()
		rateLimitMu.Lock()
		e, ok := rateLimitMap["reset:"+ip]
		if !ok {
			e = &rateLimitEntry{count: 0, windowStart: time.Now()}
			rateLimitMap["reset:"+ip] = e
		}
		if time.Since(e.windowStart) > rateLimitResetWindow {
			e.count = 0
			e.windowStart = time.Now()
		}
		e.count++
		if e.count > rateLimitMaxReset {
			rateLimitMu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": true,
				"message": "If the email exists, a reset link will be sent",
			})
			return
		}
		rateLimitMu.Unlock()
		next(w, r)
	}
}

// sanitizeInput escapes HTML to prevent XSS (Vulnerability #2).
func sanitizeInput(s string) string {
	return html.EscapeString(strings.TrimSpace(s))
}

func isDigitsOnly(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func isValidEmail(s string) bool {
	if len(s) < 5 || len(s) > 150 {
		return false
	}
	at := strings.Index(s, "@")
	if at <= 0 || at >= len(s)-1 {
		return false
	}
	dot := strings.LastIndex(s[at:], ".")
	return dot != -1 && at+dot+1 < len(s)
}

// isValidName validates name fields - only letters, spaces, hyphens, apostrophes allowed (VAPT retest).
func isValidName(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, c := range s {
		// Allow: letters (A-Z, a-z), spaces, hyphens, apostrophes
		if !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == ' ' || c == '-' || c == '\'') {
			return false
		}
	}
	return true
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

// Blocked extensions for XSS via file upload (Vulnerability #4). Never allow browser-executable types.
var blockedExtensions = map[string]bool{
	".svg": true, ".js": true, ".mjs": true, ".html": true, ".htm": true,
	".xml": true, ".xhtml": true, ".svgz": true,
}

var allowedExtensions = map[string]bool{
	".pdf": true, ".doc": true, ".docx": true, ".ppt": true, ".pptx": true,
}

func isValidFileType(filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	if blockedExtensions[ext] {
		return false
	}
	return allowedExtensions[ext]
}

// validateFileContent checks magic bytes to ensure file type matches extension (Vulnerabilities #3, #4).
func validateFileContent(content []byte, filename string) bool {
	ext := strings.ToLower(filepath.Ext(filename))
	if len(content) < 8 {
		return false
	}
	switch ext {
	case ".pdf":
		return len(content) >= 5 && string(content[:5]) == "%PDF-"
	case ".doc", ".ppt":
		// Older Office: D0 CF 11 E0 (OLE)
		return content[0] == 0xD0 && content[1] == 0xCF && content[2] == 0x11 && content[3] == 0xE0
	case ".docx", ".pptx":
		// Office Open XML: PK (ZIP)
		return content[0] == 0x50 && content[1] == 0x4B
	default:
		return false
	}
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
			failed_login_attempts INT DEFAULT 0,
			account_locked_until TIMESTAMP NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)`,
		`ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS failed_login_attempts INT DEFAULT 0`,
		`ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS account_locked_until TIMESTAMP NULL`,
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

	// Parse multipart form (max 10MB total for all files)
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		http.Error(w, "Failed to parse form data. Total file size may be too large.", http.StatusBadRequest)
		return
	}

	// Extract and sanitize form fields (Vulnerability #2: input sanitization)
	submitterName := sanitizeInput(r.FormValue("submitter_name"))
	departmentName := sanitizeInput(r.FormValue("department_name"))
	designation := sanitizeInput(r.FormValue("designation"))
	contactNumber := strings.TrimSpace(r.FormValue("contact_number"))
	email := strings.TrimSpace(strings.ToLower(r.FormValue("email")))
	title := sanitizeInput(r.FormValue("title"))
	problemDescription := sanitizeInput(r.FormValue("problem_description"))
	currentChallenges := sanitizeInput(r.FormValue("current_challenges"))
	expectedOutcome := sanitizeInput(r.FormValue("expected_outcome"))

	// Validate required fields
	if submitterName == "" || departmentName == "" || email == "" ||
		title == "" || problemDescription == "" {
		http.Error(w, "Missing required fields", http.StatusBadRequest)
		return
	}

	// Strong length checks and character validation (Vulnerability #2 - VAPT retest)
	if len(submitterName) > 150 {
		http.Error(w, "Submitter name exceeds maximum length", http.StatusBadRequest)
		return
	}
	if !isValidName(submitterName) {
		http.Error(w, "Submitter name can only contain letters, spaces, hyphens, and apostrophes", http.StatusBadRequest)
		return
	}
	if len(departmentName) > 200 {
		http.Error(w, "Department name exceeds maximum length", http.StatusBadRequest)
		return
	}
	if len(designation) > 150 {
		http.Error(w, "Designation exceeds maximum length", http.StatusBadRequest)
		return
	}
	if designation != "" && !isValidName(designation) {
		http.Error(w, "Designation can only contain letters, spaces, hyphens, and apostrophes", http.StatusBadRequest)
		return
	}
	if len(contactNumber) != 10 || !isDigitsOnly(contactNumber) {
		http.Error(w, "Contact number must be exactly 10 digits", http.StatusBadRequest)
		return
	}
	if len(email) > 150 || !isValidEmail(email) {
		http.Error(w, "Invalid email address", http.StatusBadRequest)
		return
	}
	if len(title) > 255 {
		http.Error(w, "Title exceeds maximum length", http.StatusBadRequest)
		return
	}
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

	// Handle file uploads (Vulnerabilities #3, #4: strict type and content validation)
	// Bug fixes: Validate individual file sizes (5MB max) and total size (1MB max for multiple files)
	uploadedFiles := []ProblemDocument{}
	files := r.MultipartForm.File["documents"]
	
	const maxFileSize = 5 << 20 // 5MB per file
	const maxTotalSize = 1 << 20 // 1MB total for multiple files
	
	// Calculate total size first
	totalSize := int64(0)
	for _, fileHeader := range files {
		totalSize += fileHeader.Size
	}
	
	// Validate total size for multiple files
	if len(files) > 1 && totalSize > maxTotalSize {
		http.Error(w, fmt.Sprintf("Total size of all files exceeds the limit of %d MB. Please reduce the number or size of files.", maxTotalSize/(1<<20)), http.StatusBadRequest)
		return
	}

	for _, fileHeader := range files {
		// Validate file type by extension (whitelist only)
		if !isValidFileType(fileHeader.Filename) {
			log.Printf("Rejected file type: %s", fileHeader.Filename)
			http.Error(w, "Invalid or disallowed file type. Only PDF, DOC, DOCX, PPT, PPTX are allowed.", http.StatusBadRequest)
			return
		}

		// Validate individual file size BEFORE reading (use header size first, then verify with actual content)
		if fileHeader.Size > maxFileSize {
			http.Error(w, fmt.Sprintf("File '%s' exceeds the maximum size of 5 MB. Please upload a smaller file.", fileHeader.Filename), http.StatusBadRequest)
			return
		}

		// Open uploaded file
		file, err := fileHeader.Open()
		if err != nil {
			log.Printf("Error opening file %s: %v", fileHeader.Filename, err)
			http.Error(w, fmt.Sprintf("Failed to process file '%s'. Please try again.", fileHeader.Filename), http.StatusBadRequest)
			return
		}

		// Read file content
		fileContent, err := io.ReadAll(file)
		file.Close()
		if err != nil {
			log.Printf("Error reading file %s: %v", fileHeader.Filename, err)
			http.Error(w, fmt.Sprintf("Failed to read file '%s'. Please try again.", fileHeader.Filename), http.StatusBadRequest)
			return
		}
		
		// Validate actual file size (more accurate than header size)
		actualSize := int64(len(fileContent))
		if actualSize > maxFileSize {
			http.Error(w, fmt.Sprintf("File '%s' exceeds the maximum size of 5 MB. Please upload a smaller file.", fileHeader.Filename), http.StatusBadRequest)
			return
		}

		// Server-side MIME/content validation: ensure content matches extension
		if !validateFileContent(fileContent, fileHeader.Filename) {
			log.Printf("Rejected file content mismatch: %s", fileHeader.Filename)
			http.Error(w, fmt.Sprintf("File '%s' content does not match its type. Only PDF, DOC, DOCX, PPT, PPTX are allowed.", fileHeader.Filename), http.StatusBadRequest)
			return
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
			actualSize, // Use actual size from content, not header
		).Scan(&doc.ID, &doc.UploadedAt)

		if err != nil {
			log.Printf("Error saving file metadata for %s: %v", fileHeader.Filename, err)
			continue
		}

		doc.ProblemStatementID = problemStatement.ID
		doc.OriginalFileName = fileHeader.Filename
		doc.StoredFileName = storedFileName
		doc.FileType = fileType
		doc.FileSize = actualSize // Use actual size from content

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

	if db == nil {
		log.Printf("Admin login attempted but database is not initialized")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
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

	log.Printf("Admin login attempt for email: %s", req.Email)

	// Protect database operations with a timeout to avoid hanging requests
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Get admin from database (including lockout fields)
	query := `
		SELECT id, name, email, password_hash, role, is_active, last_login_at, 
		       failed_login_attempts, account_locked_until, created_at
		FROM admin_users
		WHERE email = $1 AND is_active = true
	`

	var admin AdminUser
	var passwordHash string
	var failedAttempts int
	var accountLockedUntil *time.Time
	err := db.QueryRowContext(ctx, query, req.Email).Scan(
		&admin.ID, &admin.Name, &admin.Email, &passwordHash,
		&admin.Role, &admin.IsActive, &admin.LastLoginAt,
		&failedAttempts, &accountLockedUntil, &admin.CreatedAt,
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

	// Check if account is locked (VAPT retest: account lockout mechanism)
	now := time.Now()
	if accountLockedUntil != nil && now.Before(*accountLockedUntil) {
		remainingMinutes := int(accountLockedUntil.Sub(now).Minutes()) + 1
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"success": false,
			"message": fmt.Sprintf("Account is locked due to too many failed login attempts. Please try again after %d minutes.", remainingMinutes),
		})
		return
	}

	// If lockout period expired, reset failed attempts
	if accountLockedUntil != nil && now.After(*accountLockedUntil) {
		db.Exec("UPDATE admin_users SET failed_login_attempts = 0, account_locked_until = NULL WHERE id = $1", admin.ID)
		failedAttempts = 0
		accountLockedUntil = nil
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		// Increment failed attempts
		failedAttempts++
		const maxFailedAttempts = 5
		const lockoutDuration = 15 * time.Minute
		
		if failedAttempts >= maxFailedAttempts {
			lockUntil := now.Add(lockoutDuration)
			db.Exec("UPDATE admin_users SET failed_login_attempts = $1, account_locked_until = $2 WHERE id = $3",
				failedAttempts, lockUntil, admin.ID)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"success": false,
				"message": fmt.Sprintf("Account locked due to %d failed login attempts. Please try again after %d minutes.", maxFailedAttempts, int(lockoutDuration.Minutes())),
			})
			return
		} else {
			db.Exec("UPDATE admin_users SET failed_login_attempts = $1 WHERE id = $2", failedAttempts, admin.ID)
		}
		
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Successful login: reset failed attempts and update last login time
	updateCtx, updateCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer updateCancel()

	updateQuery := `UPDATE admin_users SET last_login_at = $1, failed_login_attempts = 0, account_locked_until = NULL WHERE id = $2`
	if _, err := db.ExecContext(updateCtx, updateQuery, now, admin.ID); err != nil {
		log.Printf("Error updating last_login_at for admin %d: %v", admin.ID, err)
	}
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
	// Admin identity comes from JWT middleware context (not request headers)
	adminID := ""
	adminEmail := ""
	if v := r.Context().Value(contextKeyAdminID); v != nil {
		if id, ok := v.(int64); ok {
			adminID = strconv.FormatInt(id, 10)
		}
	}
	if v := r.Context().Value(contextKeyAdminEmail); v != nil {
		if email, ok := v.(string); ok {
			adminEmail = email
		}
	}

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
		var designation, contactNumber, currentChallenges, expectedOutcome, assignedReviewer sql.NullString
		
		err := rows.Scan(
			&ps.ID, &ps.ReferenceID, &ps.SubmitterName, &ps.DepartmentName,
			&designation, &contactNumber, &ps.Email, &ps.Title,
			&ps.ProblemDescription, &currentChallenges, &expectedOutcome,
			&ps.SubmissionStatus, &ps.ReviewDecision, &assignedReviewer, &ps.CreatedAt,
		)
		if err != nil {
			log.Printf("Error scanning problem statement: %v", err)
			continue
		}
		
		// Convert sql.NullString to *string
		if designation.Valid {
			ps.Designation = &designation.String
		}
		if contactNumber.Valid {
			ps.ContactNumber = &contactNumber.String
		}
		if currentChallenges.Valid {
			ps.CurrentChallenges = &currentChallenges.String
		}
		if expectedOutcome.Valid {
			ps.ExpectedOutcome = &expectedOutcome.String
		}
		if assignedReviewer.Valid {
			ps.AssignedReviewer = &assignedReviewer.String
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
	var designation, contactNumber, currentChallenges, expectedOutcome, assignedReviewer sql.NullString
	
	err := db.QueryRow(query, id).Scan(
		&ps.ID, &ps.ReferenceID, &ps.SubmitterName, &ps.DepartmentName,
		&designation, &contactNumber, &ps.Email, &ps.Title,
		&ps.ProblemDescription, &currentChallenges, &expectedOutcome,
		&ps.SubmissionStatus, &ps.ReviewDecision, &assignedReviewer, &ps.CreatedAt,
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

	// Convert sql.NullString to *string
	if designation.Valid {
		ps.Designation = &designation.String
	}
	if contactNumber.Valid {
		ps.ContactNumber = &contactNumber.String
	}
	if currentChallenges.Valid {
		ps.CurrentChallenges = &currentChallenges.String
	}
	if expectedOutcome.Valid {
		ps.ExpectedOutcome = &expectedOutcome.String
	}
	if assignedReviewer.Valid {
		ps.AssignedReviewer = &assignedReviewer.String
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

	// Check if preview mode is requested (for admin dashboard preview)
	previewMode := r.URL.Query().Get("preview") == "true"
	
	dispositionFileName := originalFileName
	if dispositionFileName == "" {
		dispositionFileName = storedFileName
	}
	w.Header().Set("Content-Type", safeMIMEType(fileType))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	
	// For preview mode (admin dashboard), use inline; otherwise attachment for security (Vulnerability #4)
	if previewMode {
		w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=\"%s\"", dispositionFileName))
		// Add CSP header for PDF preview to prevent XSS
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'none'; object-src 'none';")
	} else {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", dispositionFileName))
	}

	// Serve the file
	http.ServeFile(w, r, filePath)
}

func safeMIMEType(ext string) string {
	switch strings.ToLower(ext) {
	case "pdf":
		return "application/pdf"
	case "doc":
		return "application/msword"
	case "docx":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case "ppt":
		return "application/vnd.ms-powerpoint"
	case "pptx":
		return "application/vnd.openxmlformats-officedocument.presentationml.presentation"
	default:
		return "application/octet-stream"
	}
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
	adminID := r.Context().Value(contextKeyAdminID)
	adminEmail := r.Context().Value(contextKeyAdminEmail)
	
	// Log the export action to export_logs table
	if adminID != nil && adminEmail != nil {
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

	if db == nil {
		log.Printf("Password reset requested but database is not initialized")
		http.Error(w, "Failed to process request", http.StatusInternalServerError)
		return
	}

	var req struct {
		Email string `json:"email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Use a timeout for database operations to prevent hanging
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	// Check if user exists
	var userID int64
	err := db.QueryRowContext(ctx, "SELECT id FROM admin_users WHERE email = $1", req.Email).Scan(&userID)
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
	_, err = db.ExecContext(ctx, query, userID, token, expiresAt)
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
	subject := "Problem Statement Submission Confirmation – IGNIET, K-DISC"
	body := fmt.Sprintf(`Dear %s,

Thank you for submitting your problem statement to IGNIET.
Your submission has been received successfully with the following reference ID: %s

For any queries, please contact us:
Email: ignietkdisc@gmail.com
Contact Number: +91 91886 17410

Best regards,
IGNIET Team
K-DISC`, name, referenceID)

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

// sendEmail sends an email using SMTP with timeout handling
func sendEmail(to, subject, body string) error {
	if emailConfig.Host == "" || emailConfig.Port == "" {
		log.Println("Email configuration not set, skipping email send")
		return fmt.Errorf("email not configured")
	}

	from := emailConfig.From
	
	// Create message
	msg := []byte(fmt.Sprintf("From: %s\r\n"+
		"To: %s\r\n"+
		"Subject: %s\r\n"+
		"\r\n"+
		"%s\r\n", from, to, subject, body))

	// Send email with timeout (5 seconds - fail fast if network blocked)
	addr := fmt.Sprintf("%s:%s", emailConfig.Host, emailConfig.Port)
	
	// Create a channel for the result
	done := make(chan error, 1)
	
	go func() {
		auth := smtp.PlainAuth("", emailConfig.Username, emailConfig.Password, emailConfig.Host)
		done <- smtp.SendMail(addr, auth, from, []string{to}, msg)
	}()
	
	// Wait for either completion or timeout
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("failed to send email: %v", err)
		}
		return nil
	case <-time.After(5 * time.Second):
		return fmt.Errorf("email sending timed out (SMTP port may be blocked by firewall)")
	}
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
	mux.HandleFunc("/api/admin/login", enableCORS(rateLimitLogin(adminLoginHandler)))
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
	mux.HandleFunc("/api/auth/request-password-reset", enableCORS(rateLimitPasswordReset(requestPasswordResetHandler)))
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
	
	handler := securityHeadersMiddleware(mux)
	if err := http.ListenAndServe(port, handler); err != nil {
		log.Fatal(err)
	}
}
