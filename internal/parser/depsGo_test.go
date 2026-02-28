package parser

import (
	"fmt"
	"testing"

	"github.com/rubensi-dev/github-risk-analyzer/internal/githubhelper"
	"github.com/rubensi-dev/github-risk-analyzer/internal/models"
)

func TestExtractDepsGo_Integration(t *testing.T) {
	ctx := t.Context()
	// Using a known Go repository for integration testing
	repo := models.Repository{Owner: "rubensi-dev", Name: "github-risk-analyzer"}
	client, err := githubhelper.GetAuthorizedClient(ctx)
	if err != nil {
		t.Fatalf("couldn't create client: %v", err)
	}

	result, err := ExtractDepsGo(ctx, repo, client)
	if err != nil {
		t.Fatalf("ExtractDepsGo returned unexpected error: %v", err)
	}

	fmt.Printf("result produce: %v\n", result)

	if len(result) == 0 {
		t.Error("expected at least one dependency, got 0")
	}

	foundGoGithub := false
	for _, dep := range result {
		fmt.Println(dep.Name)
		if dep.Name == "github.com/google/go-github" {
			foundGoGithub = true
		}
		if dep.Ecosystem != "go" {
			t.Errorf("expected ecosystem 'go', got %s", dep.Ecosystem)
		}
	}

	if !foundGoGithub {
		t.Error("expected to find github.com/google/go-github/github in dependencies")
	}
}

func TestExtractDepsGo_NotFound(t *testing.T) {
	ctx := t.Context()
	// Using a repo that likely doesn't have a go.mod (or doesn't exist)
	repo := models.Repository{Owner: "google", Name: "non-existent-repo-12345"}
	client, err := githubhelper.GetAuthorizedClient(ctx)
	if err != nil {
		t.Fatalf("couldn't create client: %v", err)
	}

	_, err = ExtractDepsGo(ctx, repo, client)
	if err == nil {
		t.Error("expected error for non-existent repository, got nil")
	}
}
