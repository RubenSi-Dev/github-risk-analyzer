package scanner

import (
	"testing"

	"github.com/rubensi-dev/github-risk-analyzer/internal/models"
)

func TestRunScanner(t *testing.T) {
	ctx := t.Context()

	tasks := []models.Repository{
		{Owner: "SynkraAI", Name: "aios-core"},
		{Owner: "ChromeDevTools", Name: "chrome-devtools-mcp"},
		{Owner: "is-a-dev", Name: "register"},
		{Owner: "yctimlin", Name: "mcp_excalidraw"},
		{Owner: "gnmyt", Name: "Nexterm"},
		{Owner: "module-federation", Name: "core"},
		{Owner: "aandrew-me", Name: "ytDownloader"},
		{Owner: "mui", Name: "material-ui"},
	}

	// Use 5 workers for the 8 tasks
	results, err := RunScanner(ctx, tasks, 5)
	if err != nil {
		t.Fatalf("RunScanner failed: %v", err)
	}

	if len(*results) != len(tasks) {
		t.Errorf("expected %d results, got %d", len(tasks), len(*results))
	}

	for _, res := range *results {
		if res.Repo.Name == "" {
			t.Error("expected repo name to be populated in result")
		}
		t.Logf("Scanned %s/%s: %d vulnerabilities found (err: %v)\n FOUND VULNERABILITIES: %v", res.Repo.Owner, res.Repo.Name, len(res.Vulnerabilities), res.Err, res.Vulnerabilities)
	}
}

func TestRunScanner_Empty(t *testing.T) {
	ctx := t.Context()
	tasks := []models.Repository{}
	results, err := RunScanner(ctx, tasks, 1)
	if err != nil {
		t.Fatalf("RunScanner failed: %v", err)
	}
	if len(*results) != 0 {
		t.Errorf("expected 0 results, got %d", len(*results))
	}
}
