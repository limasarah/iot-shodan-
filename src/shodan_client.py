"""
Shodan API Client Wrapper
Handles all communication with the Shodan API with rate limiting, error handling, and retry logic.
"""

import time
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import shodan

from config.settings import TIMEOUT, MAX_RESULTS

logger = logging.getLogger(__name__)


class ShodanAPIError(Exception):
    """Custom exception for Shodan API errors"""
    pass


class RateLimiter:
    """Simple rate limiter for API calls"""
    
    def __init__(self, calls_per_minute: int = 1):
        self.calls_per_minute = calls_per_minute
        self.call_times = []
    
    def wait_if_needed(self):
        """Wait if necessary to maintain rate limit"""
        now = datetime.now()
        cutoff = now - timedelta(minutes=1)
        
        # Remove old calls outside the 1-minute window
        self.call_times = [t for t in self.call_times if t > cutoff]
        
        # If we've hit the limit, wait
        if len(self.call_times) >= self.calls_per_minute:
            sleep_time = 60 - (now - self.call_times[0]).total_seconds() + 1
            if sleep_time > 0:
                logger.info(f"Rate limit reached. Waiting {sleep_time:.1f} seconds...")
                time.sleep(sleep_time)
        
        self.call_times.append(datetime.now())


class ShodanClient:
    """
    Wrapper for Shodan API with rate limiting and error handling
    """
    
    def __init__(self, api_key: str):
        """
        Initialize Shodan client
        
        Args:
            api_key: Shodan API key
            
        Raises:
            ShodanAPIError: If API key is invalid
        """
        try:
            self.api = shodan.Shodan(api_key)
            self.api_key = api_key
            self.rate_limiter = RateLimiter(calls_per_minute=1)
            logger.info("Shodan client initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize Shodan client: {e}")
            raise ShodanAPIError(f"Invalid API key or connection error: {e}")
    
    def _validate_query(self, query: str) -> bool:
        """
        Validate Shodan query format
        
        Args:
            query: Shodan query string
            
        Returns:
            True if valid, False otherwise
        """
        if not query or not isinstance(query, str):
            return False
        if len(query) > 500:
            logger.warning("Query is very long, may hit API limits")
        return True
    
    def search(
        self,
        query: str,
        limit: int = MAX_RESULTS,
        page: int = 1,
        timeout: int = TIMEOUT
    ) -> Dict[str, Any]:
        """
        Search Shodan for devices matching the query
        
        Args:
            query: Shodan query filter
            limit: Maximum results to return
            page: Page number (each page = 100 results)
            timeout: Request timeout in seconds
            
        Returns:
            Dict with 'matches' (list of devices) and 'total' (total count)
            
        Raises:
            ShodanAPIError: If search fails
        """
        if not self._validate_query(query):
            raise ShodanAPIError(f"Invalid query: {query}")
        
        try:
            self.rate_limiter.wait_if_needed()
            
            logger.info(f"Searching Shodan with query: {query}")
            logger.info(f"Limit: {limit}, Page: {page}")
            
            results = self.api.search(query, page=page, limit=limit)
            
            logger.info(f"Found {len(results['matches'])} results (total available: {results['total']})")
            
            return {
                'matches': results.get('matches', []),
                'total': results.get('total', 0),
                'query': query,
                'timestamp': datetime.now().isoformat()
            }
            
        except shodan.APIError as e:
            error_msg = f"Shodan API error: {e}"
            logger.error(error_msg)
            raise ShodanAPIError(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error during search: {e}"
            logger.error(error_msg, exc_info=True)
            raise ShodanAPIError(error_msg)
    
    def get_host_details(self, ip: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific host
        
        Args:
            ip: IP address
            
        Returns:
            Dict with detailed host information
            
        Raises:
            ShodanAPIError: If lookup fails
        """
        if not self._validate_ip(ip):
            raise ShodanAPIError(f"Invalid IP address: {ip}")
        
        try:
            self.rate_limiter.wait_if_needed()
            
            logger.debug(f"Fetching details for IP: {ip}")
            host = self.api.host(ip)
            
            return {
                'ip': ip,
                'ports': host.get('ports', []),
                'hostnames': host.get('hostnames', []),
                'org': host.get('org', 'Unknown'),
                'isp': host.get('isp', 'Unknown'),
                'country': host.get('country_name', 'Unknown'),
                'location': {
                    'latitude': host.get('latitude'),
                    'longitude': host.get('longitude')
                },
                'data': host.get('data', []),
                'timestamp': datetime.now().isoformat()
            }
            
        except shodan.APIError as e:
            error_msg = f"Failed to get host details: {e}"
            logger.error(error_msg)
            raise ShodanAPIError(error_msg)
    
    def get_account_info(self) -> Dict[str, Any]:
        """
        Get account information including API usage
        
        Args:
            Returns:
            Dict with account details
            
        Raises:
            ShodanAPIError: If lookup fails
        """
        try:
            logger.info("Fetching account information...")
            account = self.api.info()
            
            return {
                'credits_available': account.get('credits_available', 0),
                'credits_used': account.get('credits_used', 0),
                'query_credits': account.get('query_credits', 0),
                'usage': account.get('usage', 0),
                'tier': account.get('tier', 'unknown')
            }
            
        except Exception as e:
            error_msg = f"Failed to get account info: {e}"
            logger.error(error_msg)
            raise ShodanAPIError(error_msg)
    
    @staticmethod
    def _validate_ip(ip: str) -> bool:
        """
        Simple IP validation
        
        Args:
            ip: IP address string
            
        Returns:
            True if valid format, False otherwise
        """
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    def build_query(
        self,
        port: Optional[int] = None,
        product: Optional[str] = None,
        country: Optional[str] = None,
        custom: Optional[str] = None
    ) -> str:
        """
        Build a Shodan query from components
        
        Args:
            port: Port number
            product: Product name
            country: Country code
            custom: Custom query filter
            
        Returns:
            Formatted Shodan query string
        """
        parts = []
        
        if port:
            parts.append(f"port:{port}")
        if product:
            parts.append(f'product:"{product}"')
        if country:
            parts.append(f"country:{country}")
        if custom:
            parts.append(custom)
        
        query = " ".join(parts)
        logger.debug(f"Built query: {query}")
        return query
