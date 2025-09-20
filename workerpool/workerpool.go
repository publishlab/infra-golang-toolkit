//
// Worker pool with concurrency control
//

package workerpool

import (
	"sync"
)

type WorkerPool struct {
	queue  chan struct{}
	errors []error
	closed bool

	mu     sync.RWMutex
	wg     sync.WaitGroup
	closer sync.Once
}

//
// Initialize new pool
//

func New(concurrency int) *WorkerPool {
	return &WorkerPool{
		queue:  make(chan struct{}, concurrency),
		errors: make([]error, 0),
	}
}

//
// Add work function to the queue
//

func (p *WorkerPool) Submit(fn func(done func(err error)) error) {
	// Wait for open slot in queue
	p.wg.Add(1)
	p.queue <- struct{}{}

	// Callback function that signals a job is done
	done := func(err error) {
		p.wg.Done()

		p.mu.RLock()
		closed := p.closed
		p.mu.RUnlock()

		if !closed {
			<-p.queue
			if err != nil {
				p.mu.Lock()
				p.errors = append(p.errors, err)
				p.mu.Unlock()
			}
		}

	}

	// Run dispatcher function
	err := fn(done)
	if err != nil {
		done(err)
	}
}

//
// Close queue channel
//

func (p *WorkerPool) Close() {
	p.closer.Do(func() {
		p.mu.Lock()
		p.closed = true
		close(p.queue)
		p.mu.Unlock()
	})
}

//
// Wait for workers to finish and close
//

func (p *WorkerPool) Wait() {
	p.wg.Wait()
	p.Close()
}

//
// Produce list of errors from finished workers
//

func (p *WorkerPool) Errors() []error {
	p.Wait()
	return p.errors
}
