package githubhelper

import (
	"context"

	"github.com/google/go-github/github"
	"github.com/rubensi-dev/github-risk-analyzer/internal/models"
)

func GetOrganizationRepos(ctx context.Context, organization string, client *github.Client) ([]models.Repository, error) {
	opt := &github.RepositoryListByOrgOptions{ListOptions: github.ListOptions{PerPage: 100}}
	githRepos, _, err := client.Repositories.ListByOrg(ctx, organization, opt)
	if err != nil {
		return nil, err
	}

	result := make([]models.Repository, len(githRepos))
	for i, githRepo := range githRepos {
		result[i].Owner = githRepo.GetOwner().GetName()
		result[i].Name = githRepo.GetName()
	}

	return result, nil
}
