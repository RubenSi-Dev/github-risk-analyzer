package parser

import (
	"context"

	"github.com/google/go-github/github"
	"github.com/rubensi-dev/github-risk-analyzer/internal/models"
	"golang.org/x/mod/modfile"
)

func ExtractDepsGo(ctx context.Context, repo models.Repository, client *github.Client) ([]models.Dependency, error) {
	githContents, _, _, err := client.Repositories.GetContents(ctx, repo.Owner, repo.Name, "./go.mod", nil)
	if err != nil {
		return nil, err
	}

	contents, err := githContents.GetContent()
	if err != nil {
		return nil, err
	}
	f, err := modfile.Parse("go.mod", []byte(contents), nil)
	if err != nil {
		return nil, err
	}

	var deps []models.Dependency
	for _, req := range f.Require {
		dep := models.Dependency{
			Name:      req.Mod.Path,
			Ecosystem: "go",
		}
		deps = append(deps, dep)
	}

	return deps, nil
}
