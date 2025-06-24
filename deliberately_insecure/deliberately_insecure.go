package main

import (
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/user", func(w http.ResponseWriter, r *http.Request) {
		username := r.URL.Query().Get("username")
		// 🚨 SQL injection vulnerability here
		query := fmt.Sprintf("SELECT * FROM users WHERE username = '%s'", username)

		db, err := sql.Open("postgres", "user=postgres dbname=test sslmode=disable")
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()

		rows, err := db.Query(query)
		if err != nil {
			http.Error(w, "DB error", http.StatusInternalServerError)
			return
		}
		defer rows.Close()

		fmt.Fprintln(w, "Query executed")
	})

	http.ListenAndServe(":8080", nil)
}
