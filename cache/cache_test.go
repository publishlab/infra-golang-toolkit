package cache

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func BenchmarkCache(b *testing.B) {
	cache := New[[]byte](time.Minute, time.Minute, time.Hour)

	for i := 0; i < b.N; i++ {
		data, err := cache.Get("test", func() ([]byte, error) {
			return []byte(`ok`), nil
		})

		assert.Nil(b, err)
		assert.Equal(b, "ok", string(data))
	}
}

func TestCacheSingle(t *testing.T) {
	cache := New[[]byte](time.Minute, time.Minute, time.Hour)

	data, err := cache.Get("test", func() ([]byte, error) {
		return []byte(`ok`), nil
	})

	assert.Nil(t, err)
	assert.Equal(t, "ok", string(data))
}

func TestCacheWithOpts(t *testing.T) {
	cache := New[[]byte](time.Minute, time.Minute, time.Hour)

	data, err := cache.GetWithOpts(&CacheGetOpts[[]byte]{
		Key:   "test",
		TTL:   time.Minute.Nanoseconds(),
		Grace: time.Minute.Nanoseconds(),
		Generator: func() ([]byte, error) {
			return []byte(`ok`), nil
		},
	})

	assert.Nil(t, err)
	assert.Equal(t, "ok", string(data))
}

func TestCacheBool(t *testing.T) {
	cache := New[bool](time.Minute, time.Minute, time.Hour)

	data, err := cache.Get("test", func() (bool, error) {
		return true, nil
	})

	assert.Nil(t, err)
	assert.True(t, data)
}

func TestCacheHit(t *testing.T) {
	cache := New[int64](time.Minute, time.Minute, time.Hour)
	generator := func() (int64, error) {
		return cache.Get("test", func() (int64, error) {
			return rand.Int63(), nil
		})
	}

	d1, e1 := generator()
	d2, e2 := generator()

	assert.Nil(t, e1)
	assert.Nil(t, e2)
	assert.Equal(t, d1, d2)
}

func TestCacheMiss(t *testing.T) {
	cache := New[int64](0, 0, time.Hour)
	generator := func() (int64, error) {
		return cache.Get("test", func() (int64, error) {
			return rand.Int63(), nil
		})
	}

	d1, e1 := generator()
	d2, e2 := generator()

	assert.Nil(t, e1)
	assert.Nil(t, e2)
	assert.NotEqual(t, d1, d2)
}

func TestCacheGrace(t *testing.T) {
	cache := New[int64](0, time.Minute, time.Hour)
	generator := func() (int64, error) {
		return cache.Get("test", func() (int64, error) {
			return rand.Int63(), nil
		})
	}

	d1, e1 := generator()
	d2, e2 := generator()

	assert.Nil(t, e1)
	assert.Nil(t, e2)
	assert.Equal(t, d1, d2)
}

func TestCachePurgeExpired(t *testing.T) {
	cache := New[int64](0, 0, time.Hour)
	generator := func(k string) (int64, error) {
		return cache.Get(k, func() (int64, error) {
			return rand.Int63(), nil
		})
	}

	_, e1 := generator("a")
	_, e2 := generator("b")
	_, e3 := generator("c")

	assert.Nil(t, e1)
	assert.Nil(t, e2)
	assert.Nil(t, e3)

	purged := cache.purgeExpiredItems()
	assert.Equal(t, 3, purged)
}

func TestCacheError(t *testing.T) {
	cache := New[[]byte](time.Minute, time.Minute, time.Hour)

	data, err := cache.Get("test", func() ([]byte, error) {
		return nil, fmt.Errorf("oops")
	})

	assert.NotNil(t, err)
	assert.Equal(t, "oops", err.Error())
	assert.Nil(t, data)
}

func TestCacheMulti(t *testing.T) {
	var wg sync.WaitGroup
	cache := New[[]byte](time.Minute, time.Minute, time.Hour)

	for i := 0; i <= 15; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			data, err := cache.Get("test", func() ([]byte, error) {
				time.Sleep(time.Second)
				return []byte(`ok`), nil
			})

			assert.Nil(t, err)
			assert.Equal(t, "ok", string(data))
		}()
	}

	wg.Wait()
}
