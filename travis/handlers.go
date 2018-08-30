package travis

import (
	"errors"
	"net/http"
	"os/exec"

	"github.com/inconshreveable/go-update"
)

func CommandHandler(command string, onError func(error)) http.HandlerFunc {
	onReceive := func(payload *Webhook) {
		if payload.Status != statusSuccess || payload.PullRequest || payload.Branch != "master" {
			return
		}

		out, err := exec.Command(command).Output()
		if err != nil && onError != nil {
			errMsg := err.Error() + "\nStdout: " + string(out)
			if exitErr, ok := err.(*exec.ExitError); ok {
				errMsg = errMsg + "\nStderr: " + string(exitErr.Stderr)
			}
			onError(errors.New(errMsg))
		}
	}

	return NewHandler(onReceive, onError)
}

func GithubSelfUpdateHandler(url string, onError func(error)) http.HandlerFunc {
	if onError == nil {
		onError = func(e error) {}
	}

	onReceive := func(payload *Webhook) {
		if payload.Status != statusSuccess || payload.PullRequest || payload.Branch != "master" {
			return
		}

		resp, err := http.Get(url)
		if err != nil {
			onError(err)
		}
		defer resp.Body.Close()

		err = update.Apply(resp.Body, update.Options{})
		if err != nil {
			onError(err)
			return
		}
	}

	return NewHandler(onReceive, onError)
}
