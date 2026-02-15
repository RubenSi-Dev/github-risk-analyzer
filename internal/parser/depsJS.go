package parser

import (
	"context"
	"encoding/json"

	"github.com/google/go-github/github"
	"github.com/rubensi-dev/github-risk-analyzer/internal/models"
)

type packageJSON struct {
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

func ExtractDepsJS(ctx context.Context, repo models.Repository, client *github.Client) ([]models.Dependency, error) {
	githContents, _, _, err := client.Repositories.GetContents(ctx, repo.Owner, repo.Name, "./package.json", nil)
	if err != nil {
		return nil, err
	}

	contents, err := githContents.GetContent()
	if err != nil {
		return nil, err
	}

	packageJSON, err := extractDepsJS(contents)
	if err != nil {
		return nil, err
	}

	var deps []models.Dependency
	for dep := range packageJSON.Dependencies {
		deps = append(deps, models.Dependency(dep))
	}

	for dep := range packageJSON.DevDependencies {
		deps = append(deps, models.Dependency(dep))
	}

	return deps, nil
}

func extractDepsJS(contents string) (packageJSON, error) {
	var result packageJSON
	err := json.Unmarshal([]byte(contents), &result)
	return result, err
}
