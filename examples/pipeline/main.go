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
		log.Fatal("usage: pipeline URL")
	}
	engine, err := netrt.New(netrt.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close()
	task := netrt.Task{Req: &netrt.Request{URL: os.Args[1], VerifyTLS: true}, Pipeline: []netrt.Handler{func(c *netrt.Context) error {
		c.Meta["status"] = c.Resp.StatusCode
		return c.Next()
	}}}
	results, err := engine.Run(context.Background(), []netrt.Task{task})
	if err != nil {
		log.Fatal(err)
	}
	for result := range results {
		fmt.Printf("status=%v error=%v\n", result.Ctx.Meta["status"], result.Ctx.Resp.Error)
	}
}
