package main

import (
	"database/sql"
	"fmt"
	"log"
	
	"golang.org/x/crypto/bcrypt"
	_ "github.com/lib/pq"
)

func main() {
	// Generate bcrypt hash
	hash, err := bcrypt.GenerateFromPassword([]byte("password123"), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	
	// Connect to database
	connStr := "host=postgres port=5432 user=igniteuser password=ignitepass dbname=ignite sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	
	// Insert admin user
	query := `
		INSERT INTO admin_users (name, email, password_hash)
		VALUES ($1, $2, $3)
		RETURNING id
	`
	
	var id int64
	err = db.QueryRow(query, "Aagneye", "saagneye2003@gmail.com", string(hash)).Scan(&id)
	if err != nil {
		log.Fatal(err)
	}
	
	fmt.Printf("✅ Admin user created successfully with ID: %d\n", id)
	fmt.Printf("Email: saagneye2003@gmail.com\n")
	fmt.Printf("Password: password123\n")
}
