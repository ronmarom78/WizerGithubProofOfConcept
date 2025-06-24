package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func serveFile(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("file")

	// ❌ Vulnerable: no sanitization or restriction on filename
	data, err := ioutil.ReadFile("./uploads/" + filename)
	if err != nil {
		http.Error(w, "File not found", 404)
		return
	}
	w.Write(data)
}

func main() {
	// Setup: create a directory and a file to simulate upload directory
	_ = os.MkdirAll("uploads", 0755)
	_ = ioutil.WriteFile("uploads/hello.txt", []byte("Hello, world!"), 0644)

	http.HandleFunc("/download", serveFile)
	fmt.Println("Listening on http://localhost:8080/download?file=hello.txt")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
