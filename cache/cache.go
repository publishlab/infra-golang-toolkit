//
// Cache
//

package cache

import (
	"sync"
	"time"
)

type Cache[T any] struct {
	defaultTTL   int64
	defaultGrace int64
	gcInterval   int64
	lastGcTime   int64
	mu           sync.RWMutex
	items        map[string]*CacheItem[T]
}

type CacheItem[T any] struct {
	data    T
	err     error
	cond    sync.Cond
	working bool
	created int64
	expires int64
	banned  int64
}

type CacheGetOpts[T any] struct {
	Key       string
	TTL       int64
	Grace     int64
	Generator func() (T, error)
}

//
// Initialize new cache instance
//

func New[T any](defaultTTL time.Duration, defaultGrace time.Duration, gcInterval time.Duration) *Cache[T] {
	c := &Cache[T]{
		defaultTTL:   defaultTTL.Nanoseconds(),
		defaultGrace: defaultGrace.Nanoseconds(),
		gcInterval:   gcInterval.Nanoseconds(),
		lastGcTime:   time.Now().UnixNano(),
		items:        make(map[string]*CacheItem[T]),
	}

	return c
}

//
// Internal cache data writer
//

func (c *Cache[T]) write(opts *CacheGetOpts[T], data T, err error) {
	c.mu.Lock()
	now := time.Now().UnixNano()
	item := c.items[opts.Key]

	// Write item
	item.data = data
	item.err = err
	item.working = false
	item.created = now
	item.expires = (now + opts.TTL)
	item.banned = (now + opts.TTL + opts.Grace)

	c.items[opts.Key] = item

	// Trigger garbage collection
	if (c.gcInterval > 0) && (now >= (c.lastGcTime + c.gcInterval)) {
		c.lastGcTime = now
		c.purgeExpiredItems()
	}

	// Item is ready, release lock and broadcast to all readers
	c.mu.Unlock()

	item.cond.L.Lock()
	item.cond.Broadcast()
	item.cond.L.Unlock()
}

//
// Clean up all expired items
//

func (c *Cache[T]) purgeExpiredItems() int {
	now := time.Now().UnixNano()
	var expKeys []string

	// Scan for expired keys
	for k, v := range c.items {
		if !v.working && (v.banned > 0) && (now >= v.banned) {
			expKeys = append(expKeys, k)
		}
	}

	// Delete items
	for _, k := range expKeys {
		delete(c.items, k)
	}

	return len(expKeys)
}

//
// Initialize fresh cache item
//

func (c *Cache[T]) createCacheItem(opts *CacheGetOpts[T]) *CacheItem[T] {
	c.mu.Lock()
	item, exists := c.items[opts.Key]

	// Race, already exists
	if exists && item.working {
		c.mu.Unlock()
		return item
	}

	// Create placeholder object
	item = &CacheItem[T]{
		cond:    *sync.NewCond(&sync.Mutex{}),
		working: true,
	}

	c.items[opts.Key] = item
	c.mu.Unlock()

	// Data generator
	go func() {
		data, err := opts.Generator()
		c.write(opts, data, err)
	}()

	return item
}

//
// Refresh data for existing cache item
//

func (c *Cache[T]) updateCacheItem(opts *CacheGetOpts[T]) {
	c.mu.Lock()
	item := c.items[opts.Key]

	// Race, already working
	if item.working {
		c.mu.Unlock()
		return
	}

	// Update working flag
	c.items[opts.Key].working = true
	c.mu.Unlock()

	// Data generator
	go func() {
		data, err := opts.Generator()
		c.write(opts, data, err)
	}()
}

//
// Cache getter with opts
//

func (c *Cache[T]) GetWithOpts(opts *CacheGetOpts[T]) (T, error) {
	c.mu.RLock()
	item, exists := c.items[opts.Key]
	now := time.Now().UnixNano()

	var data T
	var err error
	var working bool
	var expires int64
	var banned int64

	// Read data inside lock to avoid race
	if exists {
		data = item.data
		err = item.err
		working = item.working
		expires = item.expires
		banned = item.banned
	}

	c.mu.RUnlock()

	if exists && (err == nil) {
		// Clean cache hit, nice
		if now < expires {
			return data, nil
		}

		// Graceful cache hit, maybe generate new data
		if now < banned {
			if !working {
				c.updateCacheItem(opts)
			}

			return data, nil
		}
	}

	// Complete miss, new cache item
	if !exists || !working {
		item = c.createCacheItem(opts)
	}

	// Wait for data to be generated
	item.cond.L.Lock()
	item.cond.Wait()
	item.cond.L.Unlock()

	// Read new data
	c.mu.RLock()
	data = item.data
	err = item.err
	c.mu.RUnlock()

	// Finally done
	return data, err
}

//
// Cache getter with default opts
//

func (c *Cache[T]) Get(key string, generator func() (T, error)) (T, error) {
	return c.GetWithOpts(&CacheGetOpts[T]{
		Key:       key,
		TTL:       c.defaultTTL,
		Grace:     c.defaultGrace,
		Generator: generator,
	})
}
