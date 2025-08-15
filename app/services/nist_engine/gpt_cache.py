import json
from pathlib import Path
from typing import Dict, Any, Optional
import hashlib
from datetime import datetime, timedelta

class GPTCache:
    def __init__(self, cache_dir: str = "gpt_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(exist_ok=True)
        self.cache_ttl = timedelta(days=7)  # Cache entries expire after 7 days

    def _get_cache_key(self, prompt: str) -> str:
        """Generate a unique cache key for the prompt."""
        return hashlib.md5(prompt.encode()).hexdigest()

    def _get_cache_path(self, cache_key: str) -> Path:
        """Get the path for a cache entry."""
        return self.cache_dir / f"{cache_key}.json"

    def get(self, prompt: str) -> Optional[Dict[str, Any]]:
        """
        Get a cached response for the given prompt.
        
        Args:
            prompt: The prompt text
            
        Returns:
            Cached response if found and not expired, None otherwise
        """
        cache_key = self._get_cache_key(prompt)
        cache_path = self._get_cache_path(cache_key)
        
        if not cache_path.exists():
            return None
            
        try:
            with open(cache_path, "r", encoding="utf-8") as f:
                cache_entry = json.load(f)
                
            # Check if cache entry is expired
            created_at = datetime.fromisoformat(cache_entry["created_at"])
            if datetime.now() - created_at > self.cache_ttl:
                cache_path.unlink()  # Delete expired cache
                return None
                
            return cache_entry["response"]
            
        except Exception as e:
            print(f"Error reading cache: {str(e)}")
            return None

    def set(self, prompt: str, response: Dict[str, Any]) -> None:
        """
        Cache a response for the given prompt.
        
        Args:
            prompt: The prompt text
            response: The GPT response to cache
        """
        cache_key = self._get_cache_key(prompt)
        cache_path = self._get_cache_path(cache_key)
        
        try:
            cache_entry = {
                "created_at": datetime.now().isoformat(),
                "prompt": prompt,
                "response": response
            }
            
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(cache_entry, f, indent=2)
                
        except Exception as e:
            print(f"Error writing to cache: {str(e)}")

    def clear_expired(self) -> None:
        """Clear all expired cache entries."""
        now = datetime.now()
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    cache_entry = json.load(f)
                    created_at = datetime.fromisoformat(cache_entry["created_at"])
                    if now - created_at > self.cache_ttl:
                        cache_file.unlink()
            except Exception as e:
                print(f"Error clearing cache: {str(e)}")
                continue 