package travis

import (
	"context"
	"errors"
	"log"
	"net/http"
	"strconv"
	"time"
)

// ListenAndServe is a simple helper function to create a server that handles requests on a given port/path using the handler
func ListenAndServe(port int, path string, h http.HandlerFunc) func() {
	mux := http.NewServeMux()
	mux.HandleFunc(path, recoverWrap(h))

	srv := &http.Server{
		Addr:    ":" + strconv.Itoa(port),
		Handler: mux,
		//https://blog.cloudflare.com/the-complete-guide-to-golang-net-http-timeouts/
		//https://blog.cloudflare.com/exposing-go-on-the-internet/
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  30 * time.Second,
	}

	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			log.Println(err)
		}
	}()

	return func() {
		err := srv.Shutdown(context.Background())
		if err != nil {
			log.Println(err)
		}
	}
}

func recoverWrap(f http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var err error
		defer func() {
			r := recover()
			if r != nil {
				switch t := r.(type) {
				case string:
					err = errors.New(t)
				case error:
					err = t
				default:
					err = errors.New("unknown error")
				}
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}()
		f(w, r)
	}
}
