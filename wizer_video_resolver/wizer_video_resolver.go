package wizer_video_resolver

type WizerPresentation struct {
	VulnName string
	WizerUrl string
}

var WizerDataByGithubString = map[string]WizerPresentation{
	"Database query built from user-controlled sources": {
		VulnName: "SQL Injection",
		WizerUrl: "https://www.youtube.com/watch?v=Cl0TVshoSPc",
	},
	"Uncontrolled data used in path expression": {
		VulnName: "Path Traversal",
		WizerUrl: "https://www.youtube.com/watch?v=Cl0TVshoSPc",
	},
	"Reflected cross-site scripting": {
		VulnName: "Cross-Site Scripting",
		WizerUrl: "https://www.youtube.com/watch?v=Cl0TVshoSPc",
	},
}

func GetWizerVideoByCWE(githubString string) *WizerPresentation {
	result, ok := WizerDataByGithubString[githubString]
	if !ok {
		return nil
	}
	return &result
}
