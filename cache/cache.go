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
	items        map[string]*Item[T]
}

type Opts struct {
	DefaultTTL   time.Duration
	DefaultGrace time.Duration
	GCInterval   time.Duration
}

type Item[T any] struct {
	data    T
	err     error
	working bool
	ready   *Channel
	created int64
	expires int64
	banned  int64
}

type Channel struct {
	signal chan bool
	once   sync.Once
}

type GetOpts[T any] struct {
	Key       string
	TTL       int64
	Grace     int64
	Generator func() (T, error)
}

type SetOpts[T any] struct {
	Key   string
	TTL   int64
	Grace int64
	Data  T
}

var DefaultOpts = &Opts{
	DefaultTTL:   time.Minute,
	DefaultGrace: 0,
	GCInterval:   time.Hour,
}

//
// Initialize new cache instance
//

func New[T any]() *Cache[T] {
	return NewWithOpts[T](DefaultOpts)
}

func NewWithOpts[T any](opts *Opts) *Cache[T] {
	// We always want some garbage collection
	if opts.GCInterval == 0 {
		opts.GCInterval = DefaultOpts.GCInterval
	}

	return &Cache[T]{
		defaultTTL:   opts.DefaultTTL.Nanoseconds(),
		defaultGrace: opts.DefaultGrace.Nanoseconds(),
		gcInterval:   opts.GCInterval.Nanoseconds(),
		lastGcTime:   time.Now().UnixNano(),
		items:        make(map[string]*Item[T]),
	}
}

//
// Internal cache data writer
//

func (c *Cache[T]) write(opts *GetOpts[T], data T, err error) {
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

	// Item is ready, release lock and broadcast to channel
	c.mu.Unlock()
	item.ready.once.Do(func() {
		close(item.ready.signal)
	})
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

func (c *Cache[T]) createCacheItem(opts *GetOpts[T]) *Item[T] {
	c.mu.Lock()
	item, exists := c.items[opts.Key]

	// Race, already exists
	if exists && item.working {
		c.mu.Unlock()
		return item
	}

	// Create placeholder object
	item = &Item[T]{
		working: true,
		ready: &Channel{
			signal: make(chan bool),
		},
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

func (c *Cache[T]) updateCacheItem(opts *GetOpts[T]) {
	c.mu.Lock()
	item := c.items[opts.Key]

	// Race, already working
	if item.working {
		c.mu.Unlock()
		return
	}

	// Update working flag, open new channel
	c.items[opts.Key].working = true
	c.items[opts.Key].ready = &Channel{
		signal: make(chan bool),
	}

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

func (c *Cache[T]) GetWithOpts(opts *GetOpts[T]) (T, error) {
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
	<-item.ready.signal

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
	return c.GetWithOpts(&GetOpts[T]{
		Key:       key,
		TTL:       c.defaultTTL,
		Grace:     c.defaultGrace,
		Generator: generator,
	})
}

//
// Cache setter with opts
//

func (c *Cache[T]) SetWithOpts(opts *SetOpts[T]) {
	getOpts := &GetOpts[T]{
		Key:   opts.Key,
		TTL:   opts.TTL,
		Grace: opts.Grace,
		Generator: func() (T, error) {
			return opts.Data, nil
		},
	}

	c.mu.RLock()
	item, exists := c.items[opts.Key]
	c.mu.RUnlock()

	// Update data if container exists, otherwise create
	if exists {
		c.updateCacheItem(getOpts)
	} else {
		item = c.createCacheItem(getOpts)
	}

	// Wait for data to be generated
	<-item.ready.signal
}

//
// Cache setter with default opts
//

func (c *Cache[T]) Set(key string, data T) {
	c.SetWithOpts(&SetOpts[T]{
		Key:   key,
		Data:  data,
		TTL:   c.defaultTTL,
		Grace: c.defaultGrace,
	})
}
