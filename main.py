#!/usr/bin/env python3
"""
IoT Shodan - Main Entry Point
Security research tool for identifying exposed devices using Shodan API

Phase 3: Advanced Features (Current)
"""

import sys
import time
import argparse
from pathlib import Path
from typing import Optional, List

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import validate_config, SHODAN_API_KEY, PREDEFINED_FILTERS, REPORTS_DIR
from src.logger import setup_logger
from src.shodan_client import ShodanClient, ShodanAPIError
from src.vuln_detector import VulnerabilityDetector
from src.report_generator import ReportGenerator
from src.cache import CacheManager
from src.history import HistoryDatabase
from src.notifications import NotificationManager

logger = setup_logger(__name__)


class AnalysisApplication:
    """Main application class integrating all components"""
    
    def __init__(self):
        """Initialize all components"""
        validate_config()
        self.shodan_client = ShodanClient(SHODAN_API_KEY)
        self.detector = VulnerabilityDetector()
        self.report_gen = ReportGenerator(output_dir=REPORTS_DIR)
        self.cache = CacheManager()
        self.history = HistoryDatabase()
        self.notifications = NotificationManager()
    
    def run_search_and_analysis(
        self,
        query: str,
        filter_name: Optional[str],
        limit: int,
        use_cache: bool = True,
        output_file: Optional[str] = None,
        output_format: str = "json",
        skip_analysis: bool = False,
        sort_by: Optional[str] = None,
        filter_risk: Optional[int] = None,
        min_vulns: Optional[int] = None,
    ) -> None:
        """
        Execute complete search, analysis, and reporting workflow
        
        Args:
            query: Shodan query
            filter_name: Filter name if used
            limit: Result limit
            use_cache: Whether to use cache
            output_file: Output file path
            output_format: Output format (json/csv/all)
            skip_analysis: Skip vulnerability analysis
            sort_by: Sort results by field (risk_score, port, etc)
            filter_risk: Filter by minimum risk score
            min_vulns: Filter by minimum vulnerability count
        """
        start_time = time.time()
        
        logger.info("=" * 60)
        logger.info("IoT Shodan - Exposed Device Detector")
        logger.info("Phase 3: Advanced Features ✓")
        logger.info("=" * 60)
        
        # Try to get from cache
        devices = None
        if use_cache:
            logger.info("\nChecking cache...")
            devices = self.cache.get(query, limit)
        
        # Search Shodan if not cached
        if devices is None:
            logger.info(f"\nSearching Shodan with query: {query}")
            logger.info(f"Limit: {limit}")
            
            results = self.shodan_client.search(query, limit=limit)
            devices = results['matches']
            total_found = results['total']
            
            logger.info(f"\n✓ Found {len(devices)} results")
            logger.info(f"  Total available on Shodan: {total_found}")
            
            # Cache results
            if use_cache:
                self.cache.set(query, limit, results)
        else:
            total_found = len(devices)
        
        # Analyze vulnerabilities
        stats = {}
        if not skip_analysis:
            logger.info("\nAnalyzing vulnerabilities...")
            devices = self.detector.analyze_batch(devices)
            stats = self.detector.get_summary_stats(devices)
            
            # Apply risk filtering
            if filter_risk:
                logger.info(f"Filtering by minimum risk score: {filter_risk}")
                devices = [d for d in devices if d.get('risk_score', 0) >= filter_risk]
            
            # Apply vulnerability count filtering
            if min_vulns:
                logger.info(f"Filtering by minimum {min_vulns} vulnerabilities")
                devices = [d for d in devices if len(d.get('vulnerabilities', [])) >= min_vulns]
            
            # Sort results
            if sort_by:
                self._sort_devices(devices, sort_by)
            
            self._print_summary(stats, len(devices))
        
        # Generate reports
        logger.info("\nGenerating reports...")
        execution_time = time.time() - start_time
        
        if output_format in ["json", "all"]:
            json_file = self.report_gen.generate_json(
                devices,
                query,
                filename=output_file
            )
            logger.info(f"✓ JSON report: {json_file}")
        
        if output_format in ["csv", "all"]:
            csv_file = self.report_gen.generate_csv(devices)
            logger.info(f"✓ CSV report: {csv_file}")
        
        if not skip_analysis and output_format == "json":
            txt_file = self.report_gen.generate_summary_txt(devices, query, stats)
            logger.info(f"✓ Summary report: {txt_file}")
        
        # Record in history
        logger.info("\nRecording analysis in history...")
        self.history.add_analysis(
            query=query,
            filter_name=filter_name,
            limit_results=limit,
            total_found=total_found,
            devices_analyzed=len(devices),
            execution_time=execution_time,
            stats=stats
        )
        
        # Send notifications if critical vulnerabilities found
        if not skip_analysis and stats.get('critical', 0) > 0:
            logger.info("\nSending critical vulnerability alerts...")
            critical_devices = [d for d in devices if d.get('risk_score', 0) >= 9]
            self.notifications.send_critical_alert(critical_devices, stats)
        
        logger.info(f"\n✓ Analysis complete! (Execution time: {execution_time:.2f}s)")
        logger.info(f"Reports saved to: {REPORTS_DIR}")
    
    def show_history(self, limit: int = 10) -> None:
        """Show analysis history"""
        logger.info("\n" + "=" * 60)
        logger.info("ANALYSIS HISTORY")
        logger.info("=" * 60)
        
        history = self.history.get_analysis_history(limit=limit)
        
        if not history:
            logger.info("No analysis history found")
            return
        
        for record in history:
            logger.info(
                f"\n[{record['timestamp']}] {record['query']} "
                f"({record['devices_analyzed']} devices, Risk: {record['avg_risk_score']:.1f})"
            )
    
    def show_statistics(self) -> None:
        """Show overall statistics"""
        logger.info("\n" + "=" * 60)
        logger.info("OVERALL STATISTICS")
        logger.info("=" * 60)
        
        stats = self.history.get_statistics()
        
        logger.info(f"Total Analyses: {stats.get('total_analyses', 0)}")
        logger.info(f"Unique Devices Tracked: {stats.get('total_unique_devices', 0)}")
        logger.info(f"Average Risk Score: {stats.get('average_risk_score', 0):.2f}/10")
        logger.info(f"High Risk Devices: {stats.get('high_risk_count', 0)}")
        
        logger.info("\nMost Seen Devices:")
        for device in stats.get('most_seen_devices', []):
            logger.info(f"  {device['ip']}:{device['port']} ({device['times']} times)")
        
        cache_stats = self.cache.get_stats()
        logger.info(f"\nCache: {cache_stats['total_files']} files, {cache_stats['total_size_mb']}MB")
    
    def search_devices(self, query: str) -> None:
        """Search devices in history database"""
        logger.info(f"\nSearching for: {query}")
        devices = self.history.search_devices(query)
        
        if not devices:
            logger.info("No devices found")
            return
        
        logger.info(f"\nFound {len(devices)} devices:")
        for device in devices:
            logger.info(
                f"  {device['ip']}:{device['port']} - "
                f"Risk: {device['risk_score']}/10 - "
                f"Seen: {device['times_seen']} times"
            )
    
    def list_high_risk(self, threshold: int = 7) -> None:
        """List high-risk devices from history"""
        logger.info(f"\n" + "=" * 60)
        logger.info(f"HIGH-RISK DEVICES (Risk >= {threshold})")
        logger.info("=" * 60)
        
        devices = self.history.get_high_risk_devices(risk_threshold=threshold)
        
        if not devices:
            logger.info(f"No devices with risk score >= {threshold}")
            return
        
        for device in devices:
            logger.info(
                f"{device['ip']}:{device['port']} - "
                f"Risk: {device['risk_score']}/10 - "
                f"Product: {device.get('product', 'Unknown')} - "
                f"Seen: {device['times_seen']} times"
            )
    
    @staticmethod
    def _sort_devices(devices: List, sort_by: str) -> None:
        """Sort devices by field"""
        reverse = True
        if sort_by.startswith('-'):
            sort_by = sort_by[1:]
            reverse = False
        
        devices.sort(
            key=lambda d: d.get(sort_by, 0),
            reverse=reverse
        )
        logger.info(f"Sorted by {sort_by}")
    
    @staticmethod
    def _print_summary(stats: dict, displayed_count: int) -> None:
        """Print analysis summary"""
        logger.info("\n" + "=" * 60)
        logger.info("VULNERABILITY ANALYSIS SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Devices Displayed: {displayed_count}")
        logger.info(f"Critical Risk (9-10): {stats.get('critical', 0)}")
        logger.info(f"High Risk (7-8): {stats.get('high', 0)}")
        logger.info(f"Medium Risk (5-6): {stats.get('medium', 0)}")
        logger.info(f"Low Risk (1-4): {stats.get('low', 0)}")
        logger.info(f"Total Vulnerabilities: {stats.get('total_vulnerabilities', 0)}")
        logger.info(f"Average Risk Score: {stats.get('avg_risk_score', 0):.2f}/10")
        logger.info("=" * 60)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="IoT Shodan - Exposed Device Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
SEARCH COMMANDS:
  python main.py --filter cameras --limit 50
  python main.py --query "port:554" --limit 100

ADVANCED OPTIONS:
  python main.py --filter cameras --sort-by risk_score --min-risk 7
  python main.py --filter mysql --min-vulns 2 --output custom_report.json

HISTORY & STATISTICS:
  python main.py --history
  python main.py --stats
  python main.py --search "192.168"
  python main.py --high-risk --threshold 8

CACHE MANAGEMENT:
  python main.py --cache-stats
  python main.py --clear-cache
        """
    )
    
    # Search arguments
    search_group = parser.add_argument_group('Search Options')
    search_group.add_argument('--filter', help='Use predefined filter')
    search_group.add_argument('--query', help='Custom Shodan query')
    search_group.add_argument('--limit', type=int, default=100, help='Results limit')
    
    # Output arguments
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('--output', help='Output file path')
    output_group.add_argument('--format', choices=['json', 'csv', 'all'], default='json')
    
    # Analysis arguments
    analysis_group = parser.add_argument_group('Analysis Options')
    analysis_group.add_argument('--no-analysis', action='store_true', help='Skip vulnerability analysis')
    analysis_group.add_argument('--sort-by', help='Sort by field (risk_score, port, product)')
    analysis_group.add_argument('--min-risk', type=int, help='Filter by minimum risk score')
    analysis_group.add_argument('--min-vulns', type=int, help='Filter by minimum vulnerability count')
    analysis_group.add_argument('--no-cache', action='store_true', help='Skip cache')
    
    # History arguments
    history_group = parser.add_argument_group('History & Statistics')
    history_group.add_argument('--history', action='store_true', help='Show analysis history')
    history_group.add_argument('--stats', action='store_true', help='Show statistics')
    history_group.add_argument('--search', help='Search devices in history')
    history_group.add_argument('--high-risk', action='store_true', help='List high-risk devices')
    history_group.add_argument('--threshold', type=int, default=7, help='Risk threshold')
    
    # Cache arguments
    cache_group = parser.add_argument_group('Cache Management')
    cache_group.add_argument('--cache-stats', action='store_true', help='Show cache statistics')
    cache_group.add_argument('--clear-cache', action='store_true', help='Clear cache')
    
    # System arguments
    system_group = parser.add_argument_group('System')
    system_group.add_argument('--list-filters', action='store_true', help='List filters')
    system_group.add_argument('--account-info', action='store_true', help='Account info')
    system_group.add_argument('--test-notifications', action='store_true', help='Test notifications')
    system_group.add_argument('--verbose', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    try:
        app = AnalysisApplication()
        
        # List filters
        if args.list_filters:
            logger.info("\nAvailable predefined filters:")
            for name, data in PREDEFINED_FILTERS.items():
                logger.info(f"\n  {name}")
                logger.info(f"    Name: {data.get('name')}")
                logger.info(f"    Query: {data.get('query')}")
            return 0
        
        # Account info
        if args.account_info:
            logger.info("\nFetching account information...")
            info = app.shodan_client.get_account_info()
            logger.info(f"Credits Available: {info['credits_available']}")
            logger.info(f"Query Credits: {info['query_credits']}")
            logger.info(f"Tier: {info['tier']}")
            return 0
        
        # Cache stats
        if args.cache_stats:
            stats = app.cache.get_stats()
            logger.info(f"\nCache Statistics:")
            logger.info(f"Files: {stats['total_files']}")
            logger.info(f"Size: {stats['total_size_mb']}MB")
            logger.info(f"TTL: {stats['ttl_hours']}h")
            return 0
        
        # Clear cache
        if args.clear_cache:
            deleted = app.cache.clear()
            logger.info(f"✓ Cleared {deleted} cache files")
            return 0
        
        # History
        if args.history:
            app.show_history()
            return 0
        
        # Statistics
        if args.stats:
            app.show_statistics()
            return 0
        
        # Search devices
        if args.search:
            app.search_devices(args.search)
            return 0
        
        # High-risk devices
        if args.high_risk:
            app.list_high_risk(threshold=args.threshold)
            return 0
        
        # Test notifications
        if args.test_notifications:
            logger.info("\nTesting notification connections...")
            results = app.notifications.test_connection()
            logger.info(f"Email: {'✓' if results['email'] else '✗'}")
            logger.info(f"Webhook: {'✓' if results['webhook'] else '✗'}")
            return 0
        
        # Main search and analysis
        if args.filter:
            if args.filter not in PREDEFINED_FILTERS:
                logger.error(f"Unknown filter: {args.filter}")
                return 1
            filter_config = PREDEFINED_FILTERS[args.filter]
            query = filter_config['query']
        elif args.query:
            query = args.query
        else:
            parser.print_help()
            return 1
        
        app.run_search_and_analysis(
            query=query,
            filter_name=args.filter,
            limit=args.limit,
            use_cache=not args.no_cache,
            output_file=args.output,
            output_format=args.format,
            skip_analysis=args.no_analysis,
            sort_by=args.sort_by,
            filter_risk=args.min_risk,
            min_vulns=args.min_vulns
        )
        
        return 0
        
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
