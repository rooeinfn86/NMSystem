# Network Topology Caching System

## Overview

The Network Topology Caching System is designed to improve performance and reduce loading times when accessing network diagram data. Instead of rebuilding the topology data every time a user requests it, the system caches the results for quick retrieval.

## Features

### 🚀 Performance Benefits
- **Fast Loading**: Cached topology data loads instantly instead of waiting for database queries
- **Reduced CPU Usage**: Eliminates repeated database operations and data processing
- **Lower Memory Usage**: Efficient memory management with automatic cleanup
- **Scalable**: Supports multiple networks and users simultaneously

### 🔧 Technical Features
- **Two-Level Caching**: Memory cache for fastest access, disk cache for persistence
- **Automatic Expiration**: Cache entries expire automatically based on TTL settings
- **User-Specific Caching**: Each user gets their own cache entries for security
- **Background Cleanup**: Automatic cleanup of expired entries
- **Compression**: Disk cache uses gzip compression to save space

## Architecture

### Cache Levels

1. **Memory Cache** (Primary)
   - Fastest access (microseconds)
   - Limited size (configurable, default: 100 entries)
   - Short TTL (default: 5 minutes)
   - Automatically managed with LRU eviction

2. **Disk Cache** (Secondary)
   - Persistent storage
   - Longer TTL (default: 1 hour)
   - Compressed storage to save disk space
   - Automatic cleanup of expired entries

### Cache Key Structure
```
topology_{network_id}_{user_id}
```

This ensures that:
- Each network has its own cache
- Each user has their own cache for the same network
- No data leakage between users

## Configuration

### Default Settings
```python
# Memory cache settings
memory_ttl = 300  # 5 minutes
max_memory_size = 100  # Maximum entries in memory

# Disk cache settings
disk_ttl = 3600  # 1 hour
cache_dir = "data/cache/topology"
enable_disk_cache = True

# Cleanup settings
cleanup_interval = 3600  # 1 hour between cleanup runs
```

### Customization
You can modify these settings in `app/services/topology_cache.py`:

```python
# For memory-only caching (faster, less persistent)
topology_cache = TopologyCache(
    enable_disk_cache=False,
    memory_ttl=600,  # 10 minutes
    max_memory_size=50
)

# For longer persistence
topology_cache = TopologyCache(
    memory_ttl=1800,  # 30 minutes
    disk_ttl=7200,    # 2 hours
    max_memory_size=200
)
```

## API Endpoints

### Get Topology (Cached)
```http
GET /api/v1/topology/{network_id}
```
- Returns cached topology if available
- Falls back to database query if cache miss
- Automatically caches the result

### Clear Network Cache
```http
DELETE /api/v1/topology/{network_id}/cache
```
- Clears cache for specific network and user
- Useful when topology data changes

### Cache Statistics
```http
GET /api/v1/topology/cache/stats
```
- Returns cache performance metrics
- Shows memory and disk usage

### Clear All Cache
```http
DELETE /api/v1/topology/cache/clear
```
- Clears all topology cache entries
- Use with caution in production

### Manual Cleanup
```http
POST /api/v1/topology/cache/cleanup
```
- Manually triggers cleanup of expired entries
- Usually handled automatically by background task

## Usage Examples

### Frontend Integration
```javascript
// The frontend automatically benefits from caching
// No changes needed to existing code

// Example: Loading network topology
const response = await fetch(`/api/v1/topology/${networkId}`, {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});

// First request: builds and caches topology
// Subsequent requests: returns cached data instantly
```

### Cache Management
```javascript
// Clear cache when topology changes
await fetch(`/api/v1/topology/${networkId}/cache`, {
  method: 'DELETE',
  headers: {
    'Authorization': `Bearer ${token}`
  }
});

// Check cache statistics
const stats = await fetch('/api/v1/topology/cache/stats', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});
```

## Performance Monitoring

### Cache Hit Rate
Monitor the cache hit rate to ensure the caching is effective:

```python
# In your application logs
# Look for these log messages:
# "Topology cache hit (memory) for network X"
# "Topology cache hit (disk) for network X"
# "Topology cache miss for network X"
```

### Cache Statistics
Use the statistics endpoint to monitor cache performance:

```json
{
  "cache_statistics": {
    "memory_entries": 15,
    "disk_entries": 8,
    "max_memory_size": 100,
    "memory_ttl_seconds": 300,
    "disk_ttl_seconds": 3600
  }
}
```

## Best Practices

### 1. Cache Invalidation
- Always invalidate cache when topology data changes
- Use the discovery endpoint which automatically invalidates cache
- Consider manual invalidation for configuration changes

### 2. Memory Management
- Monitor memory usage in production
- Adjust `max_memory_size` based on available RAM
- Use disk cache for larger networks

### 3. TTL Settings
- Set memory TTL shorter than disk TTL
- Consider network volatility when setting TTL
- Monitor cache hit rates to optimize TTL

### 4. Security
- Cache is user-specific for security
- No data leakage between users
- Cache keys include user ID

## Troubleshooting

### Cache Not Working
1. Check if cache directory exists: `data/cache/topology/`
2. Verify cache cleanup task is running
3. Check application logs for cache-related messages
4. Test with the cache statistics endpoint

### High Memory Usage
1. Reduce `max_memory_size`
2. Decrease `memory_ttl`
3. Enable disk cache to offload memory
4. Monitor cache statistics

### Slow Performance
1. Check cache hit rates
2. Verify disk cache is working
3. Monitor cleanup task performance
4. Consider adjusting TTL settings

## Testing

Run the cache test script to verify functionality:

```bash
python scripts/test_topology_cache.py
```

This will test:
- Basic caching functionality
- Multiple networks support
- Cache statistics
- Performance metrics
- Cleanup functionality

## Migration from Non-Cached System

The caching system is designed to be transparent to existing code:

1. **No Frontend Changes Required**: Existing API calls work unchanged
2. **Automatic Fallback**: If cache fails, system falls back to database queries
3. **Gradual Rollout**: Can be enabled/disabled without affecting functionality

## Future Enhancements

### Planned Features
- **Redis Integration**: For distributed caching across multiple instances
- **Cache Warming**: Pre-populate cache for frequently accessed networks
- **Advanced Analytics**: Detailed cache performance metrics
- **Adaptive TTL**: Dynamic TTL based on access patterns

### Monitoring Improvements
- **Prometheus Metrics**: Export cache metrics for monitoring
- **Health Checks**: Cache health monitoring endpoints
- **Alerting**: Cache performance alerts 