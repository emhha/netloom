package probe

import "sync"

// Soft404Detector tracks body-hash frequencies across a probe run and marks
// responses as soft-404 when the same hash appears more than threshold times
// with a 200 status code.
type Soft404Detector struct {
	mu        sync.Mutex
	hashCount map[string]int
	threshold int
}

// newSoft404Detector creates a detector with the given threshold (default 3).
func newSoft404Detector(threshold int) *Soft404Detector {
	if threshold <= 0 {
		threshold = 3
	}
	return &Soft404Detector{
		hashCount: make(map[string]int),
		threshold: threshold,
	}
}

// Check records the body hash and returns true when the response should be
// classified as a soft 404. Only 200-status responses are considered.
func (d *Soft404Detector) Check(statusCode int, bodyHash string) bool {
	if statusCode != 200 || bodyHash == "" {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hashCount[bodyHash]++
	return d.hashCount[bodyHash] > d.threshold
}
