package scanner

import (
	"context"
	"fmt"
	"sync"

	"github.com/google/go-github/github"
	"github.com/rubensi-dev/github-risk-analyzer/internal/githubhelper"
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
func RunScanner(ctx context.Context, tasks []models.Repository, numWorkers int) ([]Risks, error) {
	// taskchan will be populated with repos to scan
	taskChan := make(chan models.Repository, len(tasks))
	//scanTaskChan will be populated with scanjobs by the producer, which will be consumed by the consumer
	scanTaskChan := make(chan scanJob, numWorkers)
	//will be populated with the results from the consumers
	//resultsChan := make(chan Risks, numWorkers)

	// authenticate to github for more access
	client, err := githubhelper.GetAuthorizedClient(ctx)
	if err != nil {
		return nil, err
	}

	//start the producers
	var wgProducer sync.WaitGroup
	for range numWorkers {
		wgProducer.Add(1)
		go func() {
			defer wgProducer.Done()
			scanJobProducer(ctx, client, taskChan, scanTaskChan)
		}()
	}

	// close channel when producers are done
	go func() {
		wgProducer.Wait()
		close(scanTaskChan)
	}()

	// feed tasks
	for _, t := range tasks {
		taskChan <- t
	}
	close(taskChan)

	var wgConsumer sync.WaitGroup
	results := make([]Risks, 0, len(tasks))
	var muResults sync.Mutex
	// start the consumers
	for range numWorkers {
		wgConsumer.Add(1)
		go func() {
			defer wgConsumer.Done()
			scanJobConsumer(ctx, scanTaskChan, &muResults, &results)
		}()
	}
	wgConsumer.Wait()

	return results, nil
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

			deps, err := parser.ExtractDeps(ctx, repo, client)
			if err != nil {
				result.Err = err
				scanTaskChan <- result
				continue
			}

			for _, dep := range deps {
				result.Dependencies = append(result.Dependencies, models.Dependency(dep))
			}
			scanTaskChan <- result
		}
	}
}

func scanJobConsumer(ctx context.Context, scanTaskChan chan scanJob, mu *sync.Mutex, results *[]Risks) {
	for {
		select {
		case <-ctx.Done():
			return
		case scanJob, ok := <-scanTaskChan:
			if !ok {
				return
			}

			if scanJob.Err != nil {
				mu.Lock()
				*results = append(*results, Risks{Repo: scanJob.Repo, Err: scanJob.Err})
				mu.Unlock()
				continue
			}

			vulns, _ := osv.QueryVulnerabilitiesBatch(ctx, scanJob.Dependencies)

			mu.Lock()
			*results = append(*results, Risks{Repo: scanJob.Repo, Vulnerabilities: vulns, Err: ctx.Err()})
			fmt.Printf("results: %v", *results)
			mu.Unlock()
		}
	}
}
