package main

import (
	"context"
	"github.com/emhha/netloom"
	"io"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: stream URL")
	}
	engine, err := netloom.New(netloom.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()
	response, err := engine.SendStream(context.Background(), &netloom.Request{URL: os.Args[1], VerifyTLS: true})
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()
	if _, err = io.Copy(os.Stdout, response.Body); err != nil {
		log.Print(err)
	}
}
