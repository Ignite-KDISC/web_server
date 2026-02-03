package main

import (
	"database/sql"
	"flag"
	"fmt"
	"log"
	"os"
	"syscall"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
	_ "github.com/lib/pq"
)

func main() {
	email := flag.String("email", "", "Email of the admin user to reset password")
	password := flag.String("password", "", "New password (optional, will prompt if not provided)")
	
	dbHost := flag.String("db-host", "localhost", "Database host")
	dbPort := flag.String("db-port", "5432", "Database port")
	dbUser := flag.String("db-user", "igniteuser", "Database user")
	dbPassword := flag.String("db-password", "ignitepass", "Database password")
	dbName := flag.String("db-name", "ignite", "Database name")
	
	flag.Parse()

	if *email == "" {
		fmt.Println("Error: email is required")
		flag.Usage()
		os.Exit(1)
	}

	// Connect to database
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable",
		*dbHost, *dbPort, *dbUser, *dbPassword, *dbName)
	
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()

	if err = db.Ping(); err != nil {
		log.Fatalf("Error pinging database: %v", err)
	}

	// Check if user exists
	var exists bool
	err = db.QueryRow("SELECT EXISTS(SELECT 1 FROM admin_users WHERE email = $1)", *email).Scan(&exists)
	if err != nil {
		log.Fatalf("Error checking user: %v", err)
	}
	
	if !exists {
		log.Fatalf("Error: No user found with email %s", *email)
	}

	// Get password
	newPassword := *password
	if newPassword == "" {
		fmt.Print("Enter new password: ")
		passwordBytes, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatalf("Error reading password: %v", err)
		}
		newPassword = string(passwordBytes)
		fmt.Println()
		
		if len(newPassword) < 6 {
			log.Fatal("Error: Password must be at least 6 characters")
		}
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Error hashing password: %v", err)
	}

	// Update password
	_, err = db.Exec("UPDATE admin_users SET password_hash = $1 WHERE email = $2",
		string(hashedPassword), *email)
	if err != nil {
		log.Fatalf("Error updating password: %v", err)
	}

	fmt.Printf("\n✅ Password reset successfully for user: %s\n", *email)
}
