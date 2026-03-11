package githubhelper

import (
	"fmt"
	"testing"
)

func TestGetOrganizationRepos_Integration(t *testing.T) {
	ctx := t.Context()
	organization := "SynkraAI"

	client, err := GetAuthorizedClient(ctx)
	if err != nil {
		t.Fatalf("couldn't create client: %v", err)
	}

	repos, err := GetOrganizationRepos(ctx, organization, client)
	if err != nil {
		t.Fatalf("GetOrganizationRepos returned unexpected error: %v", err)
	}

	if len(repos) == 0 {
		t.Errorf("expected at least one repository for organization %s, got 0", organization)
	}
	fmt.Println(repos)

	foundRepo := false
	for _, repo := range repos {
		if repo.Name == "aios-core" {
			foundRepo = true
			break
		}
	}

	if !foundRepo {
		t.Errorf("expected to find repository 'aios-core' in organization %s", organization)
	}
}

func TestGetOrganizationRepos_NotFound(t *testing.T) {
	ctx := t.Context()
	organization := "non-existent-org-123456789"

	client, err := GetAuthorizedClient(ctx)
	if err != nil {
		t.Fatalf("couldn't create client: %v", err)
	}

	_, err = GetOrganizationRepos(ctx, organization, client)
	if err == nil {
		t.Error("expected error for non-existent organization, got nil")
	}
}
