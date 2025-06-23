package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	githubAPI   = "https://api.github.com"
	owner       = "ronmarom78"
	repo        = "WizerGithubProofOfConcept"
	issueNumber = 1
	commentText = "Hello from my Go app!"
	accessToken = "ghp_..."
)

func main() {
	url := fmt.Sprintf("%s/repos/%s/%s/issues/%d/comments", githubAPI, owner, repo, issueNumber)

	payload := map[string]string{"body": commentText}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		panic(err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
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

	if resp.StatusCode == http.StatusCreated {
		fmt.Println("✅ Comment posted successfully!")
	} else {
		fmt.Printf("❌ Failed to post comment: %s\n", resp.Status)
	}
}
