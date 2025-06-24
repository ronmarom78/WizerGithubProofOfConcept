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

type Annotation struct {
	Path            string  `json:"path"`
	BlobHref        string  `json:"blob_href"`
	StartLine       int     `json:"start_line"`
	StartColumn     int     `json:"start_column"`
	EndLine         int     `json:"end_line"`
	EndColumn       int     `json:"end_column"`
	AnnotationLevel string  `json:"annotation_level"`
	Title           string  `json:"title"`
	Message         string  `json:"message"`
	RawDetails      *string `json:"raw_details"` // Use pointer to allow null
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

type CommentBody struct {
	Body string `json:"body"`
}

type CommentResponse struct {
	ID int64 `json:"id"`
}

type PullRequestInfo struct {
	Head struct {
		Ref string `json:"ref"` // branch name
	} `json:"head"`
}
