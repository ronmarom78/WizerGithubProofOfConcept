package github_client

import (
	"WizerGithubProofOfConcept/github_model"
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	appID          = 1426527
	privateKeyPath = "/Users/ronmarom/Wizer-Development/WizerGithubProofOfConcept/private-key.pem"
)

func CreateIssue(repoFullName, installationToken, message string) error {
	url := fmt.Sprintf("https://api.github.com/repos/%s/issues", repoFullName)

	issue := map[string]string{
		"title": "Security Awareness Training available for you!",
		"body":  message,
	}
	body, err := json.Marshal(issue)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+installationToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusCreated {
		log.Println("✅ Issue created successfully!")
		log.Println(string(respBody))
	} else {
		log.Fatalf("❌ GitHub API error (%d):\n%s", resp.StatusCode, string(body))
		return errors.New(fmt.Sprintf("❌ GitHub API error (%d):\n%s", resp.StatusCode, string(body)))
	}
	return nil
}

func GetAnnotations(repoFullName, installationToken string, checkRunId int64) ([]github_model.Annotation, error) {
	url := fmt.Sprintf(
		"https://api.github.com/repos/%s/check-runs/%d/annotations", repoFullName, checkRunId,
	)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+installationToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var annotations []github_model.Annotation
	if err := json.Unmarshal(body, &annotations); err != nil {
		return nil, err
	}

	return annotations, nil
}

func GetInstallationToken(installationID float64) string {
	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatalf("error reading private key: %v", err)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		log.Fatalf("error parsing private key: %v", err)
	}

	jwtToken := generateJWT(appID, privateKey)

	url := fmt.Sprintf("https://api.github.com/app/installations/%f/access_tokens", installationID)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		log.Fatalf("failed to create token request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("failed to request access token: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		log.Fatalf("failed to get installation token: %s\n%s", resp.Status, body)
	}

	var result struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Fatalf("error parsing token response: %v", err)
	}
	return result.Token
}

func PostComment(repoFullName, installationToken string, prNumber int, message string) (int64, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/issues/%d/comments", repoFullName, prNumber)

	payload, err := json.Marshal(github_model.CommentBody{Body: message})
	if err != nil {
		return 0, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+installationToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	// Send request
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if resp.StatusCode != 201 {
		log.Fatalf("❌ GitHub API error (%d):\n%s", resp.StatusCode, string(body))
		return 0, err
	}

	var comment github_model.CommentResponse
	if err := json.Unmarshal(body, &comment); err != nil {
		return 0, err
	}

	fmt.Printf("✅ Comment posted successfully! Comment ID: %d\n", comment.ID)
	return comment.ID, nil
}

func generateJWT(appID int64, key *rsa.PrivateKey) string {
	now := time.Now()
	claims := jwt.MapClaims{
		"iat": now.Unix() - 60,  // issued at
		"exp": now.Unix() + 600, // expire after 10 minutes
		"iss": fmt.Sprintf("%d", appID),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(key)
	if err != nil {
		log.Fatalf("could not sign JWT: %v", err)
	}
	return signedToken
}
