package revoke_test

import (
	"context"
	"log"
	"net/http"

	"github.com/suzuki-shunsuke/go-revoke-github-access-token/revoke"
)

func Example() {
	client := revoke.New(http.DefaultClient) // If nil is passed, http.DefaultClient is used.
	err := client.Revoke(context.Background(), []string{
		"ghu_xxxxx",
		"gho_xxxxx",
	})
	if err != nil {
		log.Fatal(err)
	}
}
