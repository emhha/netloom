package main

import (
	"context"
	"io"
	"log"
	"netrt.local/netrt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: stream URL")
	}
	engine, err := netrt.New(netrt.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()
	response, err := engine.SendStream(context.Background(), &netrt.Request{URL: os.Args[1], VerifyTLS: true})
	if err != nil {
		log.Fatal(err)
	}
	defer response.Body.Close()
	if _, err = io.Copy(os.Stdout, response.Body); err != nil {
		log.Print(err)
	}
}
