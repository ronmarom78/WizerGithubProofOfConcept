package open_github_issue_by_app

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	appID          = 1426527
	installationID = 72684589
	repoOwner      = "ronmarom78"
	repoName       = "WizerGithubProofOfConcept"
	privateKeyPath = "/Users/ronmarom/Wizer-Development/WizerGithubProofOfConcept/private-key.pem"
)

func main() {
	OpenGithubIssueByApp(appID, privateKeyPath, installationID, fmt.Sprintf("%s/%s", repoOwner, repoName))
}

func OpenGithubIssueByApp(appID int64, privateKeyPath string, installationID float64, repoFullPath string) {
	keyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		log.Fatalf("error reading private key: %v", err)
	}
	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyData)
	if err != nil {
		log.Fatalf("error parsing private key: %v", err)
	}

	jwtToken := generateJWT(appID, privateKey)

	installationToken := getInstallationToken(jwtToken, installationID)

	createIssue(installationToken, repoFullPath)
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

func getInstallationToken(jwtToken string, installationID float64) string {
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

func createIssue(token string, repoFullPath string) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/issues", repoFullPath)

	issue := map[string]string{
		"title": "Automated security alert tracking",
		"body":  "This issue was created by a GitHub App.",
	}
	body, _ := json.Marshal(issue)

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(body))
	if err != nil {
		log.Fatalf("failed to create issue request: %v", err)
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Fatalf("failed to create issue: %v", err)
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
