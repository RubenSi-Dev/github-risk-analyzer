package parser

import (
	"context"
	"fmt"

	"github.com/google/go-github/github"
	"github.com/rubensi-dev/github-risk-analyzer/internal/models"
)

func ExtractDeps(ctx context.Context, repo models.Repository, client *github.Client) ([]models.Dependency, error) {
	langs, _, err := client.Repositories.ListLanguages(ctx, repo.Owner, repo.Name)
	if err != nil {
		return nil, fmt.Errorf("couldn't extract languages: %w", err)
	}

	_, hasJS := langs["JavaScript"]
	_, hasTS := langs["TypeScript"]
	//_, hasGo := langs["Go"]

	var deps []models.Dependency
	if hasJS || hasTS {
		var err error
		deps, err = ExtractDepsJS(ctx, repo, client)
		if err != nil {
			return nil, fmt.Errorf("couldn't extract dependencies: %w", err)
		}
	}
	return deps, nil
}
