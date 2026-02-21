package parser

import (
	"context"

	"github.com/google/go-github/github"
	"github.com/rubensi-dev/github-risk-analyzer/internal/models"
)

func ExtractDepsGo(ctx context.Context, repo models.Repository, client *github.Client) ([]models.Dependency, error) {

}
