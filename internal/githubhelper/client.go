package githubhelper

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/google/go-github/github"
	"github.com/joho/godotenv"
	"golang.org/x/oauth2"
)

func GetAuthorizedClient(ctx context.Context) (*github.Client, error) {
	// Load .env file if it exists
	err := godotenv.Load()
	if err != nil {
		return nil, fmt.Errorf("Error loading .env file: %w", err)
	}
	token := os.Getenv("GITHUB_TOKEN")
	token = strings.TrimSpace(token)

	if token == "" {
		return nil, fmt.Errorf("GITHUB_TOKEN environment variable is not set")
	}
	//token, err := ioutil.ReadFile("../../pat.txt")
	var httpClient *http.Client

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: string(token)})
	httpClient = oauth2.NewClient(ctx, ts) // oauth2 automatically adds the headers for the API call

	client := github.NewClient(httpClient)
	return client, nil
}
