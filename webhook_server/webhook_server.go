package main

import (
	"WizerGithubProofOfConcept/open_github_issue_by_app"
	"WizerGithubProofOfConcept/wizer_video_by_cwe"
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

const (
	appID          = 1426527
	privateKeyPath = "/Users/ronmarom/Wizer-Development/WizerGithubProofOfConcept/private-key.pem"
)

type Alert struct {
	vulnId      string
	description string
	severity    string
}

type CheckRunEvent struct {
	Action   string `json:"action"`
	CheckRun struct {
		Name       string `json:"name"`
		Conclusion string `json:"conclusion"` // 'success', 'failure', 'neutral'
		Status     string `json:"status"`     // 'queued', 'in_progress', 'completed'
		Output     struct {
			Summary string `json:"summary"`
		} `json:"output"`
		DetailsURL string `json:"details_url"`
	} `json:"check_run"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Installation struct {
		ID string `json:"id"`
	} `json:"installation"`
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
		var event CheckRunEvent
		err = json.NewDecoder(r.Body).Decode(&event)
		if err != nil {
			panic(err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("Check Run eventType")
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if eventType == "code_scanning_alert" {
		err = handleCodeScanningAlert(payload)
		if err != nil {
			log.Printf("%e", err)
		}
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}

func handleCodeScanningAlert(payload map[string]interface{}) error {
	alert, err := getAlertFromPayload(payload)
	if err != nil {
		return err
	}

	repository, ok := payload["repository"]
	if !ok {
		return errors.New("No repository found")
	}
	repositoryAsMap := repository.(map[string]interface{})

	repoFullName, ok := repositoryAsMap["full_name"]
	if !ok {
		return errors.New("repository has no full name")
	}
	repoFullNameStr := repoFullName.(string)
	log.Printf("repository name is %s", repoFullNameStr)

	installation, ok := payload["installation"]
	if !ok {
		return errors.New("No installation found")
	}
	installationAsMap := installation.(map[string]interface{})

	installationId, ok := installationAsMap["id"]
	if !ok {
		return errors.New("installation has no ID")
	}
	log.Printf("Hey")
	installationIdFloat := installationId.(float64)
	log.Printf("installation ID is %f", installationIdFloat)

	if alert != nil {
		log.Printf("alert %s of severity %s: %s", alert.vulnId, alert.severity, alert.description)
	}

	wizerVideoUrl := wizer_video_by_cwe.GetWizerVideoByCWE(alert.vulnId)

	open_github_issue_by_app.OpenGithubIssueByApp(
		appID, privateKeyPath, installationIdFloat, repoFullNameStr, alert.description, wizerVideoUrl,
	)

	return nil
}

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
