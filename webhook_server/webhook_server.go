package main

import (
	"WizerGithubProofOfConcept/github_client"
	"WizerGithubProofOfConcept/github_model"
	"WizerGithubProofOfConcept/wizer_video_resolver"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

const webhookSecret = "ArWm191218!"

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
		var event github_model.CheckRunEvent
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

		var prNumber int
		if len(event.CheckRun.CheckSuite.PullRequests) > 0 {
			prNumber = event.CheckRun.CheckSuite.PullRequests[0].Number
		}

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
			if prNumber > 0 {
				_, err = github_client.PostComment(event.Repository.FullName, installationToken, prNumber, message)
				if err != nil {
					log.Printf("error posting comment: %v", err)
				}
			} else {
				err = github_client.CreateIssue(event.Repository.FullName, installationToken, message)
				if err != nil {
					log.Printf("creating issue: %v", err)
				}
			}
		}
		w.WriteHeader(http.StatusOK)
		return
	}
}

func validateSignature(signature string, body []byte) bool {
	mac := hmac.New(sha256.New, []byte(webhookSecret))
	mac.Write(body)
	expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(signature), []byte(expected))
}
