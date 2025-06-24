package github_model

type Alert struct {
	Rule struct {
		ID          string `json:"id"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
	} `json:"rule"`
	Message struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations []struct {
		Path  string `json:"path"`
		Start struct {
			Line   int `json:"line"`
			Column int `json:"column"`
		} `json:"start"`
	} `json:"locations"`
	Cve   string `json:"cve"` // Optional
	Cwe   string `json:"cwe"` // Optional
	State string `json:"state"`
}

type PullRequestInfo struct {
	Head struct {
		Ref string `json:"ref"` // branch name
	} `json:"head"`
}
