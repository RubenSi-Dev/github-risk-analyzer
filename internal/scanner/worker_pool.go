package scanner

import (
	"context"
	"sync"

	"github.com/google/go-github/github"
	"github.com/rubensi-dev/github-risk-analyzer/internal/authentication"
	"github.com/rubensi-dev/github-risk-analyzer/internal/models"
	"github.com/rubensi-dev/github-risk-analyzer/internal/osv"
	"github.com/rubensi-dev/github-risk-analyzer/internal/parser"
)

// Found risks
type Risks struct {
	Repo            models.Repository
	Vulnerabilities []models.Vulnerability
	Err             error
}

// Produecer produce this, consumer consume this
type scanJob struct {
	Repo         models.Repository
	Dependencies []models.Dependency
	Err          error
}

// run the scanner on a slice of repos
func RunScanner(ctx context.Context, tasks []models.Repository, numWorkers int) (*[]Risks, error) {
	// taskchan will be populated with repos to scan
	taskChan := make(chan models.Repository, len(tasks))
	//scanTaskChan will be populated with scanjobs by the producer, which will be consumed by the consumer
	scanTaskChan := make(chan scanJob, numWorkers)
	//will be populated with the results from the consumers
	resultsChan := make(chan Risks, numWorkers)

	// authenticate to github for more access
	client, err := authentication.GetAuthorizedClient(ctx)
	if err != nil {
		return nil, err
	}

	//start the producers
	var wg sync.WaitGroup
	for range numWorkers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			scanJobProducer(ctx, client, taskChan, scanTaskChan)
		}()
	}

	// close channel when producers are done
	go func() {
		wg.Wait()
		close(scanTaskChan)
	}()

	// feed tasks
	for _, t := range tasks {
		taskChan <- t
	}
	close(taskChan)
	// start the consumers
	for range numWorkers {
		go scanJobConsumer(ctx, scanTaskChan, resultsChan)
	}

	results := make([]Risks, 0, len(tasks))

	for range tasks {
		select {
		case <-ctx.Done():
			return &results, ctx.Err()
		case res := <-resultsChan:
			results = append(results, res)
		}
	}
	return &results, nil
}

func scanJobProducer(ctx context.Context, client *github.Client, taskChan chan models.Repository, scanTaskChan chan scanJob) {
	for {
		select {
		case <-ctx.Done():
			return
		case repo, ok := <-taskChan:
			if !ok {
				return
			}

			//handle repo
			result := scanJob{Repo: repo}
			langs, _, err := client.Repositories.ListLanguages(ctx, repo.Owner, repo.Name)
			if err != nil {
				result.Err = err
				scanTaskChan <- result
				continue
			}

			_, hasJS := langs["JavaScript"]
			_, hasTS := langs["TypeScript"]
			//_, hasGo := langs["Go"]

			var deps []models.Dependency
			if hasJS || hasTS {
				var err error
				deps, err = parser.ExtractDepsJS(ctx, repo, client)
				if err != nil {
					result.Err = err
					scanTaskChan <- result
					continue
				}
			}

			for _, dep := range deps {
				result.Dependencies = append(result.Dependencies, models.Dependency(dep))
			}
			scanTaskChan <- result
		}
	}
}

func scanJobConsumer(ctx context.Context, scanTaskChan chan scanJob, resultsChan chan Risks) {
	for {
		select {
		case <-ctx.Done():
			return
		case scanJob, ok := <-scanTaskChan:
			if !ok {
				return
			}

			if scanJob.Err != nil {
				resultsChan <- Risks{Repo: scanJob.Repo, Err: scanJob.Err}
				continue
			}

			var vulns []models.Vulnerability
			var wg sync.WaitGroup
			var mu sync.Mutex
			// Limit concurrency to avoid exploding worker count (e.g., 10 concurrent checks)
			sem := make(chan struct{}, 10)

			for _, dep := range scanJob.Dependencies {
				wg.Add(1)
				go func(d models.Dependency) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()

					newVulns, err := osv.QueryVulnerabilities(ctx, dep)
					if err != nil {
						return
					}

					mu.Lock()
					vulns = append(vulns, newVulns...)
					mu.Unlock()
				}(dep)
			}
			wg.Wait()

			resultsChan <- Risks{
				Repo:            scanJob.Repo,
				Vulnerabilities: vulns,
				Err:             nil,
			}
		}
	}
}
