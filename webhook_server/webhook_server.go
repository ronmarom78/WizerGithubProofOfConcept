package main

import (
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

var webhookSecret = "ArWm191218!"

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

	event := r.Header.Get("X-GitHub-Event")
	if event == "" {
		http.Error(w, "missing event header", http.StatusBadRequest)
		return
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	log.Printf("Received event: %s", event)
	//log.Printf("Payload: %+v", payload)

	// You can filter events here:
	if event == "code_scanning_alert" {
		handleCodeScanningAlert(payload)
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "ok")
}

func handleCodeScanningAlert(payload map[string]interface{}) error {
	alert, ok := payload["alert"]
	if !ok {
		return errors.New("No alert found")
	}

	alertAsMap := alert.(map[string]interface{})
	state, ok := alertAsMap["state"]
	if !ok {
		return errors.New("alert has no status")
	}

	if state != "open" {
		return nil
	}

	rule, ok := alertAsMap["rule"]
	if !ok {
		return errors.New("alert has no rule")
	}
	ruleAsMap := rule.(map[string]interface{})

	fullDescription := ""
	fullDescriptionObj, ok := ruleAsMap["full_description"]
	if ok {
		fullDescription = fullDescriptionObj.(string)
	}

	severityLevel := "critical"
	severityLevelObj, ok := ruleAsMap["security_severity_level"]
	if ok {
		severityLevel = severityLevelObj.(string)
	}

	tags, ok := ruleAsMap["tags"]
	if !ok {
		return errors.New("alert has no tags")
	}
	tagsAsArray := tags.([]string)
	firstCwe := findCWE(tagsAsArray)

	log.Printf("alert %s of severity %s: %s", firstCwe, fullDescription, severityLevel)
	return nil
}

func findCWE(strings []string) string {
	re := regexp.MustCompile(`CWE-\d+`)
	for _, s := range strings {
		match := re.FindString(s)
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
