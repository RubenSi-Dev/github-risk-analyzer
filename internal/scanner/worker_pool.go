package scanner

import (
	"context"
	"fmt"
	"math/rand"
	"time"

	"github.com/google/go-github/github"
	"github.com/rubensi-dev/github-risk-analyzer/internal/authentication"
	"github.com/rubensi-dev/github-risk-analyzer/internal/models"
	"github.com/rubensi-dev/github-risk-analyzer/internal/parser"
)

// Found risks
type Risks struct {
	Repo            models.Repository
	Vulnerabilities []models.Vulnerability
	Err             error
}

func RunScanner(ctx context.Context, tasks []models.Repository, numWorkers int) ([]Risks, error) {
	taskChan := make(chan models.Repository, len(tasks))
	resultsChan := make(chan Risks, len(tasks))

	client, err := authentication.GetAuthorizedClient(ctx)
	if err != nil {
		return nil, err
	}

	// start the workers
	for range numWorkers {
		go repoWorker(ctx, client, taskChan, resultsChan)
	}

	// feed tasks
	for _, t := range tasks {
		taskChan <- t
	}
	close(taskChan)

	// collect results
	foundRisks := make([]Risks, len(tasks))
	for i := range tasks {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-resultsChan:
			foundRisks[i] = result
		}
	}
	return foundRisks, nil
}

func repoWorker(ctx context.Context, client *github.Client, taskChan chan models.Repository, resultsChan chan Risks) {
	for {
		select {
		case <-ctx.Done():
			return
		case repo, ok := <-taskChan:
			if !ok {
				return
			}

			//handle repo
			result := Risks{Repo: repo}
			langs, _, err := client.Repositories.ListLanguages(ctx, repo.Owner, repo.Name)
			if err != nil {
				result.Err = err
				resultsChan <- result
				continue
			}

			_, hasJS := langs["JavaScript"]
			_, hasTS := langs["TypeScript"]
			//_, hasGo := langs["Go"]

			var deps []models.Dependency
			if hasJS || hasTS {
				var err error
				deps, err = parser.ProduceDepsJS(ctx, repo, client)
				if err != nil {
					result.Err = err
					resultsChan <- result
					continue
				}
			}

			for _, dep := range deps {
				// wait a random amount of time between 1 and 3 seconds
				waitTime := time.Duration(1+rand.Intn(3)) * time.Millisecond
				select {
				case <-ctx.Done():
					return
				case <-time.After(waitTime):
					randomRisk := fmt.Sprintf("Risk found in %s", dep)
					result.Vulnerabilities = append(result.Vulnerabilities, models.Vulnerability(randomRisk))
				}
			}
			resultsChan <- result
		}
	}
}
