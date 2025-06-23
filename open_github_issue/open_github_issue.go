package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const (
	githubAPI   = "https://api.github.com"
	owner       = "ronmarom78"
	repo        = "WizerGithubProofOfConcept"
	issueNumber = 1
	commentText = "Hello from my Go app!"
	accessToken = "this-is-not-the-real-access-token"
)

func main() {
	issue := map[string]string{
		"title": "Automated security alert tracking",
		"body":  "This issue was created automatically to collect security alert messages.",
	}

	body, err := json.Marshal(issue)
	if err != nil {
		panic(err)
	}

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues", owner, repo)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		panic(err)
	}

	req.Header.Set("Authorization", "token "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusCreated {
		fmt.Println("✅ Issue created successfully!")
		fmt.Println(string(respBody))
	} else {
		fmt.Printf("❌ Failed to create issue: %s\nResponse body: %s\n", resp.Status, respBody)
	}
}
