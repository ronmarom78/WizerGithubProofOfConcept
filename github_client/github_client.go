package github_client

import (
	"WizerGithubProofOfConcept/github_model"
	"crypto/rsa"
	"encoding/json"
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

func FetchAlertsForBranch(repoFullName, installationToken string, branchName string) ([]github_model.Alert, error) {
	url := fmt.Sprintf(
		"https://api.github.com/repos/%s/code-scanning/alerts", repoFullName,
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
	var alerts []github_model.Alert
	if err := json.Unmarshal(body, &alerts); err != nil {
		return nil, err
	}

	return alerts, nil
}

func GetBranchName(repoFullName, installationToken string, prNumber int) (string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/pulls/%d", repoFullName, prNumber)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+installationToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var prInfo github_model.PullRequestInfo
	if err := json.Unmarshal(body, &prInfo); err != nil {
		return "", err
	}

	return prInfo.Head.Ref, nil
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
