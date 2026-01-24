package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

func main() {
	// Command line flags
	name := flag.String("name", "", "Admin user's name")
	email := flag.String("email", "", "Admin user's email (required)")
	role := flag.String("role", "ADMIN", "Admin user's role (default: ADMIN)")
	
	// Database connection flags
	dbHost := flag.String("db-host", getEnv("DB_HOST", "localhost"), "Database host")
	dbPort := flag.String("db-port", getEnv("DB_PORT", "5432"), "Database port")
	dbUser := flag.String("db-user", getEnv("DB_USER", "igniteuser"), "Database user")
	dbPassword := flag.String("db-password", getEnv("DB_PASSWORD", "ignitepass"), "Database password")
	dbName := flag.String("db-name", getEnv("DB_NAME", "ignite"), "Database name")

	flag.Parse()

	// Validate required fields
	if *email == "" {
		fmt.Println("Error: email is required")
		fmt.Println("\nUsage:")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Prompt for password securely
	fmt.Print("Enter password: ")
	passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Error reading password: %v", err)
	}
	fmt.Println()

	password := strings.TrimSpace(string(passwordBytes))
	if len(password) < 8 {
		log.Fatal("Error: password must be at least 8 characters")
	}

	// Confirm password
	fmt.Print("Confirm password: ")
	confirmBytes, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Error reading password confirmation: %v", err)
	}
	fmt.Println()

	if password != strings.TrimSpace(string(confirmBytes)) {
		log.Fatal("Error: passwords do not match")
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Error hashing password: %v", err)
	}

	// Connect to database
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		*dbHost, *dbPort, *dbUser, *dbPassword, *dbName)
	
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()

	// Test connection
	if err := db.Ping(); err != nil {
		log.Fatalf("Error pinging database: %v", err)
	}

	// Check if email already exists
	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM admin_users WHERE email = $1)", *email).Scan(&exists)
	if err != nil {
		log.Fatalf("Error checking existing email: %v", err)
	}
	if exists {
		log.Fatalf("Error: admin user with email '%s' already exists", *email)
	}

	// Insert the admin user
	var id int64
	err = db.QueryRow(`
		INSERT INTO admin_users (name, email, password_hash, role, is_active, created_at)
		VALUES ($1, $2, $3, $4, true, CURRENT_TIMESTAMP)
		RETURNING id
	`, *name, *email, string(hashedPassword), *role).Scan(&id)

	if err != nil {
		log.Fatalf("Error inserting admin user: %v", err)
	}

	fmt.Printf("\n✅ Admin user created successfully!\n")
	fmt.Printf("   ID:    %d\n", id)
	fmt.Printf("   Name:  %s\n", *name)
	fmt.Printf("   Email: %s\n", *email)
	fmt.Printf("   Role:  %s\n", *role)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
