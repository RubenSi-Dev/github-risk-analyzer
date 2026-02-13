package authentication

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
)

func GetAuthorizedClient(ctx context.Context) (*github.Client, error) {
	token, err := ioutil.ReadFile("../../pat.txt")
	if err != nil {
		return nil, fmt.Errorf("failed parsing token-file path: %v", err)
	}

	var httpClient *http.Client

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: string(token)})
	httpClient = oauth2.NewClient(ctx, ts) // oauth2 automatically adds the headers for the API call

	client := github.NewClient(httpClient)
	return client, nil
}
