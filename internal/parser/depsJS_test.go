package parser

import (
	"fmt"
	"testing"

	"github.com/rubensi-dev/github-risk-analyzer/internal/authentication"
	"github.com/rubensi-dev/github-risk-analyzer/internal/models"
)

func TestExtractDepsJS(t *testing.T) {
	mockPackageJSON := `{
  "name": "test-project",
  "version": "1.0.0",
  "description": "A mock package.json for testing",
  "dependencies": {
    "react": "^17.0.2",
    "lodash": "^4.17.21"
  },
  "devDependencies": {
    "typescript": "^4.3.5",
    "jest": "^27.0.6"
  }
}`

	result, err := extractDepsJS(mockPackageJSON)
	if err != nil {
		t.Fatalf("extractDepsJS returned unexpected error: %v", err)
	}

	fmt.Printf("result: %v\n", result)

	if len(result.Dependencies) != 2 {
		t.Errorf("expected 2 dependencies, got %d", len(result.Dependencies))
	}

	if len(result.DevDependencies) != 2 {
		t.Errorf("expected 2 devDependencies, got %d", len(result.DevDependencies))
	}

	if result.Dependencies["react"] != "^17.0.2" {
		t.Errorf("expected react version ^17.0.2, got %s", result.Dependencies["react"])
	}
}

func TestProduceDepsJS(t *testing.T) {
	ctx := t.Context()
	repo := models.Repository{Owner: "SynkraAI", Name: "aios-core"}
	client, err := authentication.GetAuthorizedClient(ctx)
	if err != nil {
		t.Fatalf("couldn't create client: %v", err)
	}

	result, err := ProduceDepsJS(ctx, repo, client)

	if err != nil {
		t.Fatalf("ProduceDepsJS returned unexpected error: %v", err)
	}

	fmt.Printf("result produce: %v\n", result)

	if len(result) < 2 {
		t.Errorf("expected 2 dependencies, got %d", len(result))
	}
}
