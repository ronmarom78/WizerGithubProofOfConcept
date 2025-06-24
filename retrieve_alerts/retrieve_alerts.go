package main

import (
	"WizerGithubProofOfConcept/github_client"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
)

type Alert struct {
	Rule struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
	} `json:"rule"`
	Tool struct {
		Name string `json:"name"`
	} `json:"tool"`
	CreatedAt  string `json:"created_at"`
	MostRecent bool   `json:"most_recent"`
	State      string `json:"state"`
	Instances  []any  `json:"instances"`
	Message    struct {
		Text string `json:"text"`
	} `json:"message"`
	Cwe string `json:"cwe"`
	Cve string `json:"cve"`
}

type PullRequestInfo struct {
	Head struct {
		Ref string `json:"ref"`
		SHA string `json:"sha"`
	} `json:"head"`
}

type Analysis struct {
	ID        int    `json:"id"`
	ToolName  string `json:"tool_name"`
	Ref       string `json:"ref"`
	CommitSHA string `json:"commit_sha"`
}

func getPullInfo(owner, repo, token string, prNumber int) (string, string, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/pulls/%d", owner, repo, prNumber)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var pr PullRequestInfo
	if err := json.Unmarshal(body, &pr); err != nil {
		return "", "", err
	}
	return pr.Head.Ref, pr.Head.SHA, nil
}

func getRecentAnalysisID(owner, repo, token, sha string) (int, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/code-scanning/analyses?per_page=10", owner, repo)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var analyses []Analysis
	if err := json.Unmarshal(body, &analyses); err != nil {
		return 0, err
	}

	for _, a := range analyses {
		if a.CommitSHA == sha {
			return a.ID, nil
		}
	}
	return 0, fmt.Errorf("no analysis found for commit %s", sha)
}

func main() {
	// 🔧 Replace with your values
	owner := "ronmarom78"
	repo := "WizerGithubProofOfConcept"
	//branch := "sixth_branch" // e.g., "feature/fix-cve"
	installationID := float64(72684589)
	prNumber := 9

	installationToken := github_client.GetInstallationToken(installationID)

	branch, sha, err := getPullInfo(owner, repo, installationToken, prNumber)
	if err != nil {
		log.Printf("Could not get PR info: %v", err)
		return
	}

	log.Printf(branch, sha)

	analysisID, err := getRecentAnalysisID(owner, repo, installationToken, "230a8ba1110051b701536b44137ac73049153248")
	if err != nil {
		log.Printf("Could not get SARIF analysis: %v", err)
		return
	}

	log.Printf("%d", analysisID)

	//url := fmt.Sprintf("https://api.github.com/repos/%s/%s/code-scanning/alerts?ref=refs/heads/%s", owner, repo, branch)
	//
	//req, err := http.NewRequest("GET", url, nil)
	//if err != nil {
	//	log.Fatalf("Failed to create request: %v", err)
	//}
	//req.Header.Set("Authorization", "Bearer "+installationToken)
	//req.Header.Set("Accept", "application/vnd.github+json")
	//
	//resp, err := http.DefaultClient.Do(req)
	//if err != nil {
	//	log.Fatalf("Failed to call GitHub API: %v", err)
	//}
	//defer resp.Body.Close()
	//
	//body, _ := io.ReadAll(resp.Body)
	//
	//if resp.StatusCode != 200 {
	//	log.Fatalf("GitHub API error: %s\nResponse: %s", resp.Status, string(body))
	//}
	//
	//var alerts []Alert
	//if err := json.Unmarshal(body, &alerts); err != nil {
	//	log.Fatalf("Failed to unmarshal response: %v", err)
	//}
	//
	//if len(alerts) == 0 {
	//	fmt.Println("✅ No alerts found for this branch.")
	//	return
	//}
	//
	//fmt.Printf("🚨 Found %d alerts on branch %s:\n", len(alerts), branch)
	//for _, alert := range alerts {
	//	fmt.Println("------------------------------------------------")
	//	fmt.Printf("Rule ID:     %s\n", alert.Rule.ID)
	//	fmt.Printf("Severity:    %s\n", alert.Rule.Severity)
	//	fmt.Printf("Description: %s\n", alert.Rule.Description)
	//	fmt.Printf("Tool:        %s\n", alert.Tool.Name)
	//	fmt.Printf("State:       %s\n", alert.State)
	//	fmt.Printf("Message:     %s\n", alert.Message.Text)
	//	if alert.Cve != "" {
	//		fmt.Printf("CVE:         %s\n", alert.Cve)
	//	}
	//	if alert.Cwe != "" {
	//		fmt.Printf("CWE:         %s\n", alert.Cwe)
	//	}
	//}
}
