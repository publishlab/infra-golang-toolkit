package workerpool

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func BenchmarkPool(b *testing.B) {
	pool := New(10)
	count := 0
	var mu sync.Mutex

	for i := 0; i < b.N; i++ {
		pool.Submit(func(done func(err error)) error {
			go func() {
				mu.Lock()
				count++
				mu.Unlock()
				done(nil)
			}()

			return nil
		})
	}

	pool.Wait()
	assert.Equal(b, count, b.N)
}

func TestPool(t *testing.T) {
	for _, n := range []int{5, 15, 30} {
		pool := New(3)
		count := 0
		var mu sync.Mutex

		for i := 0; i < n; i++ {
			pool.Submit(func(done func(err error)) error {
				go func() {
					mu.Lock()
					count++
					mu.Unlock()
					done(nil)
				}()

				return nil
			})
		}

		pool.Wait()
		assert.Equal(t, count, n)
		assert.Empty(t, pool.Errors())
	}
}

func TestPoolErrorReturn(t *testing.T) {
	pool := New(3)

	for i := 0; i < 10; i++ {
		pool.Submit(func(done func(err error)) error {
			return fmt.Errorf("big error")
		})
	}

	errors := pool.Errors()
	assert.Equal(t, len(errors), 10)
	for _, err := range errors {
		assert.Equal(t, err.Error(), "big error")
	}
}

func TestPoolErrorAsync(t *testing.T) {
	pool := New(3)

	for i := 0; i < 10; i++ {
		pool.Submit(func(done func(err error)) error {
			go func() {
				done(fmt.Errorf("big error"))
			}()

			return nil
		})
	}

	errors := pool.Errors()
	assert.Equal(t, len(errors), 10)
	for _, err := range errors {
		assert.Equal(t, err.Error(), "big error")
	}
}

func TestPoolSingle(t *testing.T) {
	for _, n := range []int{1, 2, 3} {
		pool := New(1)
		start := time.Now()

		for i := 0; i < n; i++ {
			pool.Submit(func(done func(err error)) error {
				go func() {
					time.Sleep(100 * time.Millisecond)
					done(nil)
				}()

				return nil
			})
		}

		pool.Wait()
		delta := time.Since(start)
		floor := time.Duration(n*100) * time.Millisecond
		ceil := time.Duration((n+1)*100) * time.Millisecond

		assert.GreaterOrEqual(t, delta, floor)
		assert.LessOrEqual(t, delta, ceil)
	}
}

func TestPoolDouble(t *testing.T) {
	for _, n := range []int{2, 4, 6} {
		pool := New(2)
		start := time.Now()

		for i := 0; i < n; i++ {
			pool.Submit(func(done func(err error)) error {
				go func() {
					time.Sleep(100 * time.Millisecond)
					done(nil)
				}()

				return nil
			})
		}

		pool.Wait()
		delta := time.Since(start)
		floor := time.Duration(n*50) * time.Millisecond
		ceil := time.Duration((n+2)*50) * time.Millisecond

		assert.GreaterOrEqual(t, delta, floor)
		assert.LessOrEqual(t, delta, ceil)
	}
}

func TestPoolTriple(t *testing.T) {
	for _, n := range []int{3, 6, 9} {
		pool := New(3)
		start := time.Now()

		for i := 0; i < n; i++ {
			pool.Submit(func(done func(err error)) error {
				go func() {
					time.Sleep(100 * time.Millisecond)
					done(nil)
				}()

				return nil
			})
		}

		pool.Wait()
		delta := time.Since(start)
		floor := time.Duration(n*33) * time.Millisecond
		ceil := time.Duration((n+3)*33) * time.Millisecond

		assert.GreaterOrEqual(t, delta, floor)
		assert.LessOrEqual(t, delta, ceil)
	}
}
