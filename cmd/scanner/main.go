package main

import (
	"context"
	"fmt"

	"github.com/rubensi-dev/github-risk-analyzer/internal/githubhelper"
	"github.com/rubensi-dev/github-risk-analyzer/internal/models"
	"github.com/rubensi-dev/github-risk-analyzer/internal/scanner"
)

var OrganizationToScan = "SynkraAI"

func main() {
	ctx := context.Background()
	client, err := githubhelper.GetAuthorizedClient(ctx)
	if err != nil {
		fmt.Println(err)
	}

	tasks, err := githubhelper.GetOrganizationRepos(ctx, OrganizationToScan, client)
	if err != nil {
		fmt.Println(err)
	}

	risks, err := scanner.RunScanner(ctx, tasks, 5, client)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println(resultsToString(models.Report{Organization: OrganizationToScan, FoundRisks: risks}))
}

func resultsToString(report models.Report) string {
	result := fmt.Sprintf("Results for organization: %v\n", report.Organization)
	for _, risks := range report.FoundRisks {
		result += fmt.Sprintf("		Found (%v) vulnerabilities in repo %v\n", len(risks.Vulnerabilities), risks.Repo.Name)
		for _, vuln := range risks.Vulnerabilities {
			result += fmt.Sprintf("			%v: %v -- %v -- %v\n", vuln.ID, vuln.Severity, vuln.Details)
		}
	}
	return result
}
