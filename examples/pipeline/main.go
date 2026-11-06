package main

import (
	"context"
	"fmt"
	"github.com/emhha/netloom"
	"log"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: pipeline URL")
	}
	engine, err := netloom.New(netloom.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()
	task := netloom.Task{Req: &netloom.Request{URL: os.Args[1], VerifyTLS: true}, Pipeline: []netloom.Handler{func(c *netloom.Context) error {
		c.Meta["status"] = c.Resp.StatusCode
		return c.Next()
	}}}
	results, err := engine.Run(context.Background(), []netloom.Task{task})
	if err != nil {
		log.Fatal(err)
	}
	for result := range results {
		fmt.Printf("status=%v error=%v\n", result.Ctx.Meta["status"], result.Ctx.Resp.Error)
	}
}
