package common

import (
	"container/list"
	"hash/fnv"
	"sync"
	"time"
)

// lruEntry 存储缓存的键值对及过期信息
type lruEntry[K comparable, V any] struct {
	key       K
	value     V
	expiresAt int64 // UnixNano 格式的过期时间戳
}

// lruShard 是分段锁中的一个独立 LRU 分段
type lruShard[K comparable, V any] struct {
	mu        sync.Mutex
	capacity  int
	items     map[K]*list.Element
	evictList *list.List
}

// ShardedLruCache 是一个高性能、并发安全且支持过期时间的分段 LRU 缓存
type ShardedLruCache[K comparable, V any] struct {
	shards    []*lruShard[K, V]
	shardMask uint32
	hashFunc  func(K) uint32
	ttl       time.Duration
}

// NewShardedLru 创建一个新的分段 LRU 缓存
// totalCapacity: 建议设置为 2 的幂次，例如 1024
// shardCount: 分段数量，必须是 2 的幂次 (如 16, 32, 64) 以优化性能
// ttl: 缓存条目的生存周期
// hashFn: 针对键类型的哈希函数
func NewShardedLru[K comparable, V any](totalCapacity int, shardCount int, ttl time.Duration, hashFn func(K) uint32) *ShardedLruCache[K, V] {
	// 确保 shardCount 是 2 的幂次以便使用位运算代替取模
	if shardCount <= 0 || (shardCount&(shardCount-1)) != 0 {
		shardCount = 32
	}

	s := &ShardedLruCache[K, V]{
		shards:    make([]*lruShard[K, V], shardCount),
		shardMask: uint32(shardCount - 1),
		hashFunc:  hashFn,
		ttl:       ttl,
	}

	shardCap := totalCapacity / shardCount
	if shardCap < 1 {
		shardCap = 1
	}

	for i := 0; i < shardCount; i++ {
		s.shards[i] = &lruShard[K, V]{
			capacity:  shardCap,
			items:     make(map[K]*list.Element),
			evictList: list.New(),
		}
	}
	return s
}

// Get 获取缓存值。如果过期或不存在，返回零值和 false
func (s *ShardedLruCache[K, V]) Get(key K) (V, bool) {
	shard := s.shards[s.hashFunc(key)&s.shardMask]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	if ent, ok := shard.items[key]; ok {
		entry := ent.Value.(*lruEntry[K, V])

		// 惰性删除：检查是否过期
		if time.Now().UnixNano() > entry.expiresAt {
			shard.evictList.Remove(ent)
			delete(shard.items, key)
			var zero V
			return zero, false
		}

		// 命中：移动到链表头部
		shard.evictList.MoveToFront(ent)
		return entry.value, true
	}

	var zero V
	return zero, false
}

// Add 向缓存中添加或更新键值对
func (s *ShardedLruCache[K, V]) Add(key K, value V) {
	shard := s.shards[s.hashFunc(key)&s.shardMask]

	shard.mu.Lock()
	defer shard.mu.Unlock()

	expiresAt := time.Now().Add(s.ttl).UnixNano()

	if ent, ok := shard.items[key]; ok {
		// 更新现有记录
		shard.evictList.MoveToFront(ent)
		entry := ent.Value.(*lruEntry[K, V])
		entry.value = value
		entry.expiresAt = expiresAt
		return
	}

	// 插入新记录
	newEnt := &lruEntry[K, V]{
		key:       key,
		value:     value,
		expiresAt: expiresAt,
	}
	element := shard.evictList.PushFront(newEnt)
	shard.items[key] = element

	// 检查容量并执行 LRU 淘汰
	if shard.evictList.Len() > shard.capacity {
		if back := shard.evictList.Back(); back != nil {
			shard.evictList.Remove(back)
			delete(shard.items, back.Value.(*lruEntry[K, V]).key)
		}
	}
}

// --- 辅助函数：针对 routeCacheKey 的零分配哈希实现 ---

type routeCacheKey struct {
	qname string
	qtype uint16
}

// RouteCacheKeyHash 实现了零分配的 FNV-1a 哈希
func RouteCacheKeyHash(k routeCacheKey) uint32 {
	h := fnv.New32a()
	// WriteString 内部不涉及字节切片拷贝，能减少内存分配
	h.Write([]byte(k.qname))
	h.Write([]byte{byte(k.qtype >> 8), byte(k.qtype)})
	return h.Sum32()
}
