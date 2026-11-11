package dirscan

import (
	"context"
	"sync"

	"github.com/emhha/netloom"
)

type scanJob struct {
	sequence   int
	path       string
	requestDir string
	url        string
}

type scanReply struct {
	job  scanJob
	resp *netloom.Response
	err  error
}

func scanConcurrency(threads int) int {
	if threads <= 0 {
		return 30
	}
	return threads
}

// scanDirectory owns a bounded dispatch/reorder window. Workers only send;
// consume runs exclusively on the coordinator, in dispatch order. Completed
// out-of-order responses retain their window slot until consumed, so a slow
// first request cannot cause an unbounded backlog of response bodies.
//
// A false consume result stops admission permanently for this directory and
// cancels its in-flight requests. Every admitted job still reports exactly once;
// successful in-flight replies are consumed even after stopping or cancellation.
func (s *scanner) scanDirectory(ctx context.Context, dir string, words []string, consume func(scanReply) ([]string, bool)) {
	if ctx.Err() != nil || len(words) == 0 {
		return
	}
	limit := scanConcurrency(s.cfg.Threads)
	workCtx, cancel := context.WithCancel(ctx)
	jobs := make(chan scanJob)
	replies := make(chan scanReply, limit)
	var workers sync.WaitGroup
	for i := 0; i < limit; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for job := range jobs {
				reply := scanReply{job: job, err: workCtx.Err()}
				if reply.err == nil {
					reply.resp, reply.err = s.engine.Send(workCtx, s.buildRequest(job.url))
				}
				// Never drop a completion on cancellation: the coordinator must
				// release each admitted slot and collect completed evidence.
				replies <- reply
			}
		}()
	}
	defer func() {
		cancel()
		close(jobs)
		workers.Wait()
	}()

	var extra []string
	wordIndex, sent, consumed, outstanding := 0, 0, 0, 0
	completed := make(map[int]scanReply, limit)
	stopped := false
	ctxDone := ctx.Done()
	for {
		if ctx.Err() != nil && !stopped {
			stopped = true
			cancel()
		}
		if outstanding == 0 && (stopped || len(extra) == 0 && wordIndex == len(words)) {
			return
		}

		var send chan scanJob
		job := scanJob{sequence: sent, requestDir: dir}
		fromCrawl := len(extra) > 0
		if !stopped && outstanding < limit && (fromCrawl || wordIndex < len(words)) {
			if fromCrawl {
				job.path, job.requestDir = extra[0], "/"
			} else {
				job.path = words[wordIndex]
			}
			job.url = joinURL(s.cfg.BaseURL, job.requestDir, job.path)
			send = jobs
		}
		select {
		case <-ctxDone:
			stopped = true
			cancel()
			ctxDone = nil
		case send <- job:
			if fromCrawl {
				extra[0] = ""
				extra = extra[1:]
			} else {
				wordIndex++
			}
			sent++
			outstanding++
		case reply := <-replies:
			completed[reply.job.sequence] = reply
			for {
				next, ok := completed[consumed]
				if !ok {
					break
				}
				delete(completed, consumed)
				consumed++
				outstanding--
				links, keepGoing := consume(next)
				if !keepGoing {
					stopped = true
					cancel()
				}
				if !stopped {
					extra = append(extra, links...)
				}
			}
		}
	}
}
