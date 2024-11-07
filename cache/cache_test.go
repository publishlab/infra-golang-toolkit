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
	cache := New[[]byte]()

	for i := 0; i < b.N; i++ {
		data, err := cache.Get("test", func() ([]byte, error) {
			return []byte(`ok`), nil
		})

		assert.NoError(b, err)
		assert.Equal(b, "ok", string(data))
	}
}

func TestCacheSingle(t *testing.T) {
	cache := New[[]byte]()

	data, err := cache.Get("test", func() ([]byte, error) {
		return []byte(`ok`), nil
	})

	assert.NoError(t, err)
	assert.Equal(t, "ok", string(data))
}

func TestCacheWithOpts(t *testing.T) {
	cache := NewWithOpts[[]byte](&Opts{
		DefaultTTL:   time.Minute,
		DefaultGrace: time.Minute,
		GCInterval:   time.Hour,
	})

	data, err := cache.Get("test", func() ([]byte, error) {
		return []byte(`ok`), nil
	})

	assert.NoError(t, err)
	assert.Equal(t, "ok", string(data))
}

func TestCacheGetWithOpts(t *testing.T) {
	cache := New[[]byte]()

	data, err := cache.GetWithOpts(&GetOpts[[]byte]{
		Key:   "test",
		TTL:   time.Minute.Nanoseconds(),
		Grace: time.Minute.Nanoseconds(),
		Generator: func() ([]byte, error) {
			return []byte(`ok`), nil
		},
	})

	assert.NoError(t, err)
	assert.Equal(t, "ok", string(data))
}

func TestCacheBool(t *testing.T) {
	cache := New[bool]()

	data, err := cache.Get("test", func() (bool, error) {
		return true, nil
	})

	assert.NoError(t, err)
	assert.True(t, data)
}

func TestCacheHit(t *testing.T) {
	cache := New[int64]()
	generator := func() (int64, error) {
		return cache.Get("test", func() (int64, error) {
			return rand.Int63(), nil
		})
	}

	d1, e1 := generator()
	d2, e2 := generator()

	assert.NoError(t, e1)
	assert.NoError(t, e2)
	assert.Equal(t, d1, d2)
}

func TestCacheMiss(t *testing.T) {
	cache := NewWithOpts[int64](&Opts{
		DefaultTTL: 0,
	})

	generator := func() (int64, error) {
		return cache.Get("test", func() (int64, error) {
			return rand.Int63(), nil
		})
	}

	d1, e1 := generator()
	d2, e2 := generator()

	assert.NoError(t, e1)
	assert.NoError(t, e2)
	assert.NotEqual(t, d1, d2)
}

func TestCacheGrace(t *testing.T) {
	cache := NewWithOpts[int64](&Opts{
		DefaultTTL:   0,
		DefaultGrace: time.Minute,
	})

	generator := func() (int64, error) {
		return cache.Get("test", func() (int64, error) {
			return rand.Int63(), nil
		})
	}

	d1, e1 := generator()
	d2, e2 := generator()

	assert.NoError(t, e1)
	assert.NoError(t, e2)
	assert.Equal(t, d1, d2)
}

func TestCacheSet(t *testing.T) {
	cache := New[int64]()
	cache.Set("test", 42)

	data, err := cache.Get("test", func() (int64, error) {
		return 123, nil
	})

	assert.NoError(t, err)
	assert.Equal(t, int64(42), data)
}

func TestCacheSetUpdate(t *testing.T) {
	cache := New[int64]()
	generator := func() (int64, error) {
		return cache.Get("test", func() (int64, error) {
			return 123, nil
		})
	}

	d1, e1 := generator()
	assert.NoError(t, e1)
	assert.Equal(t, int64(123), d1)

	cache.Set("test", 42)

	d2, e2 := generator()
	assert.NoError(t, e2)
	assert.Equal(t, int64(42), d2)
}

func TestCacheSetWithOpts(t *testing.T) {
	cache := New[int64]()
	generator := func() (int64, error) {
		return cache.Get("test", func() (int64, error) {
			return 123, nil
		})
	}

	d1, e1 := generator()
	assert.NoError(t, e1)
	assert.Equal(t, int64(123), d1)

	cache.SetWithOpts(&SetOpts[int64]{
		Key:   "test",
		Data:  42,
		TTL:   time.Minute.Nanoseconds(),
		Grace: time.Minute.Nanoseconds(),
	})

	d2, e2 := generator()
	assert.NoError(t, e2)
	assert.Equal(t, int64(42), d2)
}

func TestCachePurgeExpired(t *testing.T) {
	cache := NewWithOpts[int64](&Opts{
		DefaultTTL: 0,
	})

	generator := func(k string) (int64, error) {
		return cache.Get(k, func() (int64, error) {
			return rand.Int63(), nil
		})
	}

	_, e1 := generator("a")
	_, e2 := generator("b")
	_, e3 := generator("c")

	assert.NoError(t, e1)
	assert.NoError(t, e2)
	assert.NoError(t, e3)

	purged := cache.purgeExpiredItems()
	assert.Equal(t, 3, purged)
}

func TestCacheError(t *testing.T) {
	cache := New[[]byte]()

	data, err := cache.Get("test", func() ([]byte, error) {
		return nil, fmt.Errorf("oops")
	})

	assert.Error(t, err)
	assert.Equal(t, "oops", err.Error())
	assert.Nil(t, data)
}

func TestCacheMulti(t *testing.T) {
	var wg sync.WaitGroup
	cache := New[[]byte]()

	for i := 0; i <= 15; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			data, err := cache.Get("test", func() ([]byte, error) {
				time.Sleep(time.Second)
				return []byte(`ok`), nil
			})

			assert.NoError(t, err)
			assert.Equal(t, "ok", string(data))
		}()
	}

	wg.Wait()
}

func TestCacheRace(t *testing.T) {
	var wg sync.WaitGroup
	cache := New[int64]()
	generator := func(key int) (int64, error) {
		return cache.Get(fmt.Sprintf("%d", key), func() (int64, error) {
			return rand.Int63(), nil
		})
	}

	for i := 0; i <= 15; i++ {
		key := rand.Int()

		for x := 0; x <= 30; x++ {
			wg.Add(1)

			go func() {
				defer wg.Done()
				_, err := generator(key)
				assert.NoError(t, err)
			}()
		}
	}

	wg.Wait()
}
