package main

//wileedot
import (
	"fmt"
	"log"
	"net/http"

	wileedot "github.com/opd-ai/wileedot"
)

func main() {
	cfg := wileedot.Config{
		Domain:         "localhost",
		AllowedDomains: []string{"localhost"},
		CertDir:        "./",
		Email:          "example@example.com",
	}
	listener, err := wileedot.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	hi := &hello{}
	http.Serve(listener, hi)
}

type hello struct{}

func (h *hello) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, %s!", r.URL.Path[1:])
}
