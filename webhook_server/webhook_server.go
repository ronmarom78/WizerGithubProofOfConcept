package main

import (
	"WizerGithubProofOfConcept/github_client"
	"WizerGithubProofOfConcept/wizer_video_resolver"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
)

const webhookSecret = "ArWm191218!"

type Alert struct {
	vulnId      string
	description string
	severity    string
}

type CheckRunEvent struct {
	Action     string          `json:"action"`
	CheckRun   CheckRunPayload `json:"check_run"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Installation struct {
		ID float64 `json:"id"`
	} `json:"installation"`
}

type CheckRunPayload struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
	Output     struct {
		Summary string `json:"summary"`
	} `json:"output"`
	CheckSuite struct {
		PullRequests []struct {
			Number int `json:"number"`
		} `json:"pull_requests"`
	} `json:"check_suite"`
}

func main() {
	http.HandleFunc("/webhook", handleWebhook)

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Listening on :%s...", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	signature := r.Header.Get("X-Hub-Signature-256")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read body", http.StatusInternalServerError)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body)) // restore body for reuse

	if !validateSignature(signature, body) {
		http.Error(w, "invalid signature", http.StatusForbidden)
		return
	}

	eventType := r.Header.Get("X-GitHub-Event")
	if eventType == "" {
		http.Error(w, "missing eventType header", http.StatusBadRequest)
		return
	}

	log.Printf("Received eventType: %s", eventType)

	if eventType == "check_run" {
		//var payload map[string]interface{}
		//if err := json.Unmarshal(body, &payload); err != nil {
		//	http.Error(w, "invalid JSON", http.StatusBadRequest)
		//	return
		//}
		var event CheckRunEvent
		err = json.NewDecoder(r.Body).Decode(&event)
		if err != nil {
			log.Printf("%v", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if event.CheckRun.Status != "completed" {
			w.WriteHeader(http.StatusOK)
			return
		}

		installationToken := github_client.GetInstallationToken(event.Installation.ID)

		annotations, err := github_client.GetAnnotations(
			event.Repository.FullName, installationToken, event.CheckRun.ID,
		)
		if err != nil {
			log.Println("Error fetching annotations: %v", err)
			w.WriteHeader(http.StatusOK)
			return
		}

		if len(event.CheckRun.CheckSuite.PullRequests) == 0 {
			log.Println("No pull request associated with this check run.")
			w.WriteHeader(http.StatusOK)
			return
		}
		prNumber := event.CheckRun.CheckSuite.PullRequests[0].Number

		for _, annotation := range annotations {
			wizerData := wizer_video_resolver.GetWizerVideoByCWE(annotation.Title)
			if wizerData == nil {
				log.Printf("No Wizer video available for annotation \"%s\"", annotation.Title)
				continue
			}
			message := fmt.Sprintf(
				"We have noticed that you have a code security vulnerability: %s\nFor your convenience, Wizer training has a video about how to avoid such issues at %s",
				wizerData.VulnName,
				wizerData.WizerUrl,
			)
			github_client.PostComment(event.Repository.FullName, installationToken, prNumber, message)
		}

		//if len(event.CheckRun.CheckSuite.PullRequests) == 0 {
		//	log.Println("No pull request associated with this check run.")
		//	w.WriteHeader(http.StatusOK)
		//	return
		//}
		//prNumber := event.CheckRun.CheckSuite.PullRequests[0].Number
		//
		//
		//branchName, err := github_client.GetBranchName(event.Repository.FullName, installationToken, prNumber)
		//if err != nil {
		//	log.Println("Error fetching branch name")
		//	w.WriteHeader(http.StatusOK)
		//	return
		//}
		//
		//alerts, err := github_client.FetchAlertsForBranch(event.Repository.FullName, installationToken, branchName)
		//if err != nil {
		//	log.Println("Error fetching alerts")
		//	w.WriteHeader(http.StatusOK)
		//	return
		//}
		//
		//for _, alert := range alerts {
		//	fmt.Println("------------------------------------------------")
		//	fmt.Printf("Severity:    %s\n", alert.Rule.Severity)
		//	fmt.Printf("Description: %s\n", alert.Rule.Description)
		//	fmt.Printf("Message:     %s\n", alert.Message.Text)
		//	if alert.Cve != "" {
		//		fmt.Printf("CVE:         %s\n", alert.Cve)
		//	}
		//	if alert.Cwe != "" {
		//		fmt.Printf("CWE:         %s\n", alert.Cwe)
		//	}
		//	if len(alert.Locations) > 0 {
		//		loc := alert.Locations[0]
		//		fmt.Printf("File:        %s:%d:%d\n", loc.Path, loc.Start.Line, loc.Start.Column)
		//	}
		//}

		w.WriteHeader(http.StatusOK)
		return
	}

	//var payload map[string]interface{}
	//if err := json.Unmarshal(body, &payload); err != nil {
	//	http.Error(w, "invalid JSON", http.StatusBadRequest)
	//	return
	//}
	//
	//if eventType == "code_scanning_alert" {
	//	err = handleCodeScanningAlert(payload)
	//	if err != nil {
	//		log.Printf("%e", err)
	//	}
	//}
	//
	//w.WriteHeader(http.StatusOK)
	//fmt.Fprintln(w, "ok")
}

//func handleCodeScanningAlert(payload map[string]interface{}) error {
//	alert, err := getAlertFromPayload(payload)
//	if err != nil {
//		return err
//	}
//
//	repository, ok := payload["repository"]
//	if !ok {
//		return errors.New("No repository found")
//	}
//	repositoryAsMap := repository.(map[string]interface{})
//
//	repoFullName, ok := repositoryAsMap["full_name"]
//	if !ok {
//		return errors.New("repository has no full name")
//	}
//	repoFullNameStr := repoFullName.(string)
//	log.Printf("repository name is %s", repoFullNameStr)
//
//	installation, ok := payload["installation"]
//	if !ok {
//		return errors.New("No installation found")
//	}
//	installationAsMap := installation.(map[string]interface{})
//
//	installationId, ok := installationAsMap["id"]
//	if !ok {
//		return errors.New("installation has no ID")
//	}
//	log.Printf("Hey")
//	installationIdFloat := installationId.(float64)
//	log.Printf("installation ID is %f", installationIdFloat)
//
//	if alert != nil {
//		log.Printf("alert %s of severity %s: %s", alert.vulnId, alert.severity, alert.description)
//	}
//
//	wizerVideoUrl := wizer_video_resolver.GetWizerVideoByCWE(alert.vulnId)
//
//	open_github_issue_by_app.OpenGithubIssueByApp(
//		appID, privateKeyPath, installationIdFloat, repoFullNameStr, alert.description, wizerVideoUrl,
//	)
//
//	return nil
//}

func getAlertFromPayload(payload map[string]interface{}) (*Alert, error) {
	alert, ok := payload["alert"]
	if !ok {
		return nil, errors.New("No alert found")
	}

	alertAsMap := alert.(map[string]interface{})
	state, ok := alertAsMap["state"]
	if !ok {
		return nil, errors.New("alert has no status")
	}

	if state != "open" {
		return nil, nil
	}

	rule, ok := alertAsMap["rule"]
	if !ok {
		return nil, errors.New("alert has no rule")
	}
	ruleAsMap := rule.(map[string]interface{})

	result := Alert{
		severity: "critical",
	}

	fullDescriptionObj, ok := ruleAsMap["full_description"]
	if ok {
		result.description = fullDescriptionObj.(string)
	}

	severityLevelObj, ok := ruleAsMap["security_severity_level"]
	if ok {
		result.severity = severityLevelObj.(string)
	}

	tags, ok := ruleAsMap["tags"]
	if !ok {
		return nil, errors.New("alert has no tags")
	}
	tagsAsArray := tags.([]interface{})
	result.vulnId = findCWE(tagsAsArray)

	return &result, nil
}

func findCWE(strings []interface{}) string {
	re := regexp.MustCompile(`cwe-\d+`)
	for _, s := range strings {
		match := re.FindString(s.(string))
		if match != "" {
			return match
		}
	}
	return ""
}

func validateSignature(signature string, body []byte) bool {
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expected))
}
