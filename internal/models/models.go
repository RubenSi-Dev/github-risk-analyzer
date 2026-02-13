package models

import "fmt"

type Vulnerability string
type Dependency string

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
