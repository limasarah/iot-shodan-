"""
Caching System
Provides file-based caching for Shodan search results to avoid redundant API calls
"""

import json
import logging
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
import hashlib

logger = logging.getLogger(__name__)


class CacheManager:
    """
    Manages caching of Shodan search results to reduce API usage.
    Uses JSON files with TTL (time-to-live) validation.
    """
    
    def __init__(self, cache_dir: Optional[Path] = None, ttl_hours: int = 24):
        """
        Initialize cache manager
        
        Args:
            cache_dir: Directory for cache files (default: ./cache)
            ttl_hours: Cache time-to-live in hours (default: 24)
        """
        self.cache_dir = cache_dir or Path('./cache')
        self.cache_dir.mkdir(exist_ok=True)
        self.ttl_hours = ttl_hours
        
        logger.info(f"Cache manager initialized: {self.cache_dir} (TTL: {ttl_hours}h)")
    
    def _get_cache_key(self, query: str, limit: int) -> str:
        """
        Generate cache key from query and limit
        
        Args:
            query: Shodan query string
            limit: Result limit
            
        Returns:
            Hash-based cache key
        """
        key_str = f"{query}_{limit}"
        return hashlib.md5(key_str.encode()).hexdigest()
    
    def _get_cache_path(self, cache_key: str) -> Path:
        """Get full cache file path"""
        return self.cache_dir / f"cache_{cache_key}.json"
    
    def get(self, query: str, limit: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached search results if valid
        
        Args:
            query: Shodan query string
            limit: Result limit
            
        Returns:
            Cached result dict or None if expired/missing
        """
        cache_key = self._get_cache_key(query, limit)
        cache_path = self._get_cache_path(cache_key)
        
        if not cache_path.exists():
            logger.debug(f"Cache miss: {query}")
            return None
        
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                cached = json.load(f)
            
            # Check TTL
            cached_time = datetime.fromisoformat(cached['cached_at'])
            ttl_delta = timedelta(hours=self.ttl_hours)
            
            if datetime.now() - cached_time > ttl_delta:
                logger.info(f"Cache expired: {query}")
                cache_path.unlink()  # Delete expired cache
                return None
            
            match_count = cached.get('matches', 0)
            logger.info(f"Cache hit: {query} ({match_count} results)")
            return cached['data']
            
        except (json.JSONDecodeError, IOError, KeyError) as e:
            logger.warning(f"Cache read error: {e}")
            return None
    
    def set(self, query: str, limit: int, data: Dict[str, Any]) -> bool:
        """
        Cache search results
        
        Args:
            query: Shodan query string
            limit: Result limit
            data: Search result data to cache
            
        Returns:
            True if successful, False otherwise
        """
        cache_key = self._get_cache_key(query, limit)
        cache_path = self._get_cache_path(cache_key)
        
        try:
            cache_entry = {
                'query': query,
                'limit': limit,
                'cached_at': datetime.now().isoformat(),
                'matches': len(data.get('matches', [])),
                'data': data
            }
            
            with open(cache_path, 'w', encoding='utf-8') as f:
                json.dump(cache_entry, f, indent=2)
            
            logger.info(f"Cache saved: {query}")
            return True
            
        except IOError as e:
            logger.error(f"Failed to write cache: {e}")
            return False
    
    def clear(self, pattern: Optional[str] = None) -> int:
        """
        Clear cache files
        
        Args:
            pattern: Optional pattern to match cache files (default: clear all)
            
        Returns:
            Number of files deleted
        """
        deleted = 0
        
        for cache_file in self.cache_dir.glob('cache_*.json'):
            if pattern is None or pattern in cache_file.name:
                try:
                    cache_file.unlink()
                    deleted += 1
                except OSError as e:
                    logger.warning(f"Failed to delete cache file: {e}")
        
        logger.info(f"Cleared {deleted} cache files")
        return deleted
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get cache statistics
        
        Returns:
            Dict with cache stats (total files, size, etc)
        """
        cache_files = list(self.cache_dir.glob('cache_*.json'))
        total_size = sum(f.stat().st_size for f in cache_files if f.exists())
        
        return {
            'total_files': len(cache_files),
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'ttl_hours': self.ttl_hours,
            'cache_dir': str(self.cache_dir)
        }
