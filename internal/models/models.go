package models

import "fmt"

type Dependency struct {
	Name      string
	Ecosystem string // e.g., "npm", "Go", "Maven", "PyPI"
}

type Vulnerability struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Details  string `json:"details"`
	Severity string `json:"severity"` // e.g., "CRITICAL", "HIGH", "MEDIUM", "LOW"
}
type Repository struct {
	Owner string
	Name  string
}

func (r Repository) GetUrl() string {
	return fmt.Sprintf("https://github.com/%s/%s", r.Owner, r.Name)
}

func UrlToRepo(url string) (Repository, error) {
	var owner, name string
	_, err := fmt.Sscanf(url, "https://www.github.com/%s/%s", &owner, &name)
	if err != nil {
		_, err = fmt.Sscanf(url, "https://github.com/%s/%s", &owner, &name)
		if err != nil {
			return Repository{}, fmt.Errorf("invalid github url: %s", url)
		}
	}
	return Repository{Owner: owner, Name: name}, nil
}
