import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from pathlib import Path
import logging
from threading import Lock
import pickle
import gzip

logger = logging.getLogger(__name__)

class TopologyCache:
    """
    Efficient caching system for network topology data.
    Uses memory cache with optional disk persistence and automatic cleanup.
    """
    
    def __init__(self, 
                 cache_dir: str = "data/cache/topology",
                 memory_ttl: int = 300,  # 5 minutes in memory
                 disk_ttl: int = 3600,   # 1 hour on disk
                 max_memory_size: int = 100,  # Max number of cached topologies in memory
                 enable_disk_cache: bool = True):
        """
        Initialize the topology cache.
        
        Args:
            cache_dir: Directory for disk cache storage
            memory_ttl: Time to live for memory cache entries (seconds)
            disk_ttl: Time to live for disk cache entries (seconds)
            max_memory_size: Maximum number of topologies to keep in memory
            enable_disk_cache: Whether to enable disk persistence
        """
        self.cache_dir = Path(cache_dir)
        self.memory_ttl = timedelta(seconds=memory_ttl)
        self.disk_ttl = timedelta(seconds=disk_ttl)
        self.max_memory_size = max_memory_size
        self.enable_disk_cache = enable_disk_cache
        
        # Memory cache: {cache_key: {'data': topology_data, 'created_at': datetime, 'access_count': int}}
        self._memory_cache: Dict[str, Dict[str, Any]] = {}
        self._cache_lock = Lock()
        
        # Create cache directory if disk cache is enabled
        if self.enable_disk_cache:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            logger.info(f"Topology cache initialized with disk storage at {self.cache_dir}")
        else:
            logger.info("Topology cache initialized with memory-only storage")
    
    def _get_cache_key(self, network_id: int, user_id: int) -> str:
        """Generate a unique cache key for the network topology."""
        key_data = f"topology_{network_id}_{user_id}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _get_disk_cache_path(self, cache_key: str) -> Path:
        """Get the path for a disk cache entry."""
        return self.cache_dir / f"{cache_key}.pkl.gz"
    
    def _compress_data(self, data: Dict[str, Any]) -> bytes:
        """Compress topology data for disk storage."""
        return gzip.compress(pickle.dumps(data))
    
    def _decompress_data(self, compressed_data: bytes) -> Dict[str, Any]:
        """Decompress topology data from disk storage."""
        return pickle.loads(gzip.decompress(compressed_data))
    
    def get(self, network_id: int, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Get cached topology data for a network.
        
        Args:
            network_id: The network ID
            user_id: The user ID (for access control)
            
        Returns:
            Cached topology data if found and not expired, None otherwise
        """
        cache_key = self._get_cache_key(network_id, user_id)
        
        with self._cache_lock:
            # Check memory cache first
            if cache_key in self._memory_cache:
                entry = self._memory_cache[cache_key]
                if datetime.now() - entry['created_at'] <= self.memory_ttl:
                    # Update access count and return data
                    entry['access_count'] += 1
                    logger.debug(f"Topology cache hit (memory) for network {network_id}")
                    return entry['data']
                else:
                    # Remove expired entry
                    del self._memory_cache[cache_key]
            
            # Check disk cache if enabled
            if self.enable_disk_cache:
                cache_path = self._get_disk_cache_path(cache_key)
                if cache_path.exists():
                    try:
                        with open(cache_path, 'rb') as f:
                            compressed_data = f.read()
                        
                        cache_entry = self._decompress_data(compressed_data)
                        created_at = datetime.fromisoformat(cache_entry['created_at'])
                        
                        # Check if disk cache entry is expired
                        if datetime.now() - created_at <= self.disk_ttl:
                            # Move to memory cache
                            self._add_to_memory_cache(cache_key, cache_entry['data'])
                            logger.debug(f"Topology cache hit (disk) for network {network_id}")
                            return cache_entry['data']
                        else:
                            # Remove expired disk cache
                            cache_path.unlink()
                            logger.debug(f"Removed expired disk cache for network {network_id}")
                    except Exception as e:
                        logger.warning(f"Error reading disk cache for network {network_id}: {e}")
                        if cache_path.exists():
                            cache_path.unlink()
        
        logger.debug(f"Topology cache miss for network {network_id}")
        return None
    
    def set(self, network_id: int, user_id: int, topology_data: Dict[str, Any]) -> None:
        """
        Cache topology data for a network.
        
        Args:
            network_id: The network ID
            user_id: The user ID
            topology_data: The topology data to cache
        """
        cache_key = self._get_cache_key(network_id, user_id)
        
        with self._cache_lock:
            # Add to memory cache
            self._add_to_memory_cache(cache_key, topology_data)
            
            # Add to disk cache if enabled
            if self.enable_disk_cache:
                try:
                    cache_entry = {
                        'data': topology_data,
                        'created_at': datetime.now().isoformat(),
                        'network_id': network_id,
                        'user_id': user_id
                    }
                    
                    cache_path = self._get_disk_cache_path(cache_key)
                    compressed_data = self._compress_data(cache_entry)
                    
                    with open(cache_path, 'wb') as f:
                        f.write(compressed_data)
                    
                    logger.debug(f"Cached topology data for network {network_id} (memory + disk)")
                except Exception as e:
                    logger.warning(f"Error writing to disk cache for network {network_id}: {e}")
            else:
                logger.debug(f"Cached topology data for network {network_id} (memory only)")
    
    def _add_to_memory_cache(self, cache_key: str, topology_data: Dict[str, Any]) -> None:
        """Add data to memory cache with size management."""
        # Remove oldest entries if cache is full
        if len(self._memory_cache) >= self.max_memory_size:
            # Find the least recently used entry
            oldest_key = min(self._memory_cache.keys(), 
                           key=lambda k: self._memory_cache[k]['access_count'])
            del self._memory_cache[oldest_key]
            logger.debug("Removed oldest entry from memory cache")
        
        # Add new entry
        self._memory_cache[cache_key] = {
            'data': topology_data,
            'created_at': datetime.now(),
            'access_count': 1
        }
    
    def invalidate(self, network_id: int, user_id: int = None) -> None:
        """
        Invalidate cache entries for a network.
        
        Args:
            network_id: The network ID
            user_id: Specific user ID to invalidate (None for all users)
        """
        with self._cache_lock:
            if user_id is not None:
                # Invalidate specific user's cache
                cache_key = self._get_cache_key(network_id, user_id)
                self._memory_cache.pop(cache_key, None)
                
                if self.enable_disk_cache:
                    cache_path = self._get_disk_cache_path(cache_key)
                    if cache_path.exists():
                        cache_path.unlink()
                
                logger.debug(f"Invalidated topology cache for network {network_id}, user {user_id}")
            else:
                # Invalidate all users' cache for this network
                keys_to_remove = []
                for cache_key in list(self._memory_cache.keys()):
                    # Extract network_id from cache key (this is a simplified approach)
                    # In a real implementation, you might want to store network_id in the cache entry
                    keys_to_remove.append(cache_key)
                
                for cache_key in keys_to_remove:
                    self._memory_cache.pop(cache_key, None)
                
                if self.enable_disk_cache:
                    # Remove all disk cache files for this network
                    for cache_file in self.cache_dir.glob("*.pkl.gz"):
                        try:
                            with open(cache_file, 'rb') as f:
                                compressed_data = f.read()
                            cache_entry = self._decompress_data(compressed_data)
                            if cache_entry.get('network_id') == network_id:
                                cache_file.unlink()
                        except Exception:
                            pass
                
                logger.debug(f"Invalidated all topology cache for network {network_id}")
    
    def clear(self) -> None:
        """Clear all cache entries."""
        with self._cache_lock:
            self._memory_cache.clear()
            
            if self.enable_disk_cache:
                for cache_file in self.cache_dir.glob("*.pkl.gz"):
                    try:
                        cache_file.unlink()
                    except Exception as e:
                        logger.warning(f"Error removing cache file {cache_file}: {e}")
            
            logger.info("Cleared all topology cache")
    
    def cleanup_expired(self) -> None:
        """Clean up expired cache entries."""
        now = datetime.now()
        
        with self._cache_lock:
            # Clean memory cache
            expired_keys = [
                key for key, entry in self._memory_cache.items()
                if now - entry['created_at'] > self.memory_ttl
            ]
            for key in expired_keys:
                del self._memory_cache[key]
            
            # Clean disk cache
            if self.enable_disk_cache:
                for cache_file in self.cache_dir.glob("*.pkl.gz"):
                    try:
                        with open(cache_file, 'rb') as f:
                            compressed_data = f.read()
                        cache_entry = self._decompress_data(compressed_data)
                        created_at = datetime.fromisoformat(cache_entry['created_at'])
                        
                        if now - created_at > self.disk_ttl:
                            cache_file.unlink()
                    except Exception as e:
                        logger.warning(f"Error cleaning up cache file {cache_file}: {e}")
                        # Remove corrupted cache files
                        try:
                            cache_file.unlink()
                        except Exception:
                            pass
        
        if expired_keys:
            logger.info(f"Cleaned up {len(expired_keys)} expired cache entries")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        with self._cache_lock:
            memory_size = len(self._memory_cache)
            disk_size = 0
            
            if self.enable_disk_cache:
                disk_size = len(list(self.cache_dir.glob("*.pkl.gz")))
            
            return {
                'memory_entries': memory_size,
                'disk_entries': disk_size,
                'max_memory_size': self.max_memory_size,
                'memory_ttl_seconds': self.memory_ttl.total_seconds(),
                'disk_ttl_seconds': self.disk_ttl.total_seconds()
            }

# Global cache instance
topology_cache = TopologyCache() 