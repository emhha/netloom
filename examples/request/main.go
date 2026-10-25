package main

import (
	"context"
	"fmt"
	"log"
	"netrt.local/netrt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: request URL")
	}
	engine, err := netrt.New(netrt.Config{Retries: -1})
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()
	response, err := engine.Send(context.Background(), &netrt.Request{URL: os.Args[1], VerifyTLS: true})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("status=%d bytes=%d truncated=%v\n", response.StatusCode, len(response.Body), response.BodyTruncated)
}
