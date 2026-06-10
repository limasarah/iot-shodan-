#!/usr/bin/env python3
"""
IoT Shodan - Main Entry Point
Security research tool for identifying exposed devices using Shodan API

Phase 2: Core Functionality (Current)
"""

import sys
import argparse
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import validate_config, SHODAN_API_KEY, PREDEFINED_FILTERS, REPORTS_DIR
from src.logger import setup_logger
from src.shodan_client import ShodanClient, ShodanAPIError
from src.vuln_detector import VulnerabilityDetector
from src.report_generator import ReportGenerator

logger = setup_logger(__name__)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="IoT Shodan - Exposed Device Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Search for RTSP cameras and analyze
  python main.py --filter cameras --limit 50

  # Search with custom Shodan query
  python main.py --query "port:554" --limit 50 --output reports/cameras.json

  # List available predefined filters
  python main.py --list-filters

  # Get account information
  python main.py --account-info
        """
    )
    
    parser.add_argument(
        "--filter",
        help="Use predefined filter (see --list-filters)",
        default=None
    )
    parser.add_argument(
        "--query",
        help="Custom Shodan query",
        default=None
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=100,
        help="Maximum results to fetch (default: 100)"
    )
    parser.add_argument(
        "--output",
        help="Output file path (default: auto-generated in reports/)",
        default=None
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv", "all"],
        default="json",
        help="Output format (default: json)"
    )
    parser.add_argument(
        "--list-filters",
        action="store_true",
        help="List available predefined filters"
    )
    parser.add_argument(
        "--account-info",
        action="store_true",
        help="Show account information and credits"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    parser.add_argument(
        "--no-analysis",
        action="store_true",
        help="Skip vulnerability analysis, just export raw results"
    )
    
    args = parser.parse_args()
    
    try:
        # Validate configuration
        validate_config()
        logger.info("Configuration validated successfully")
        
        logger.info("=" * 60)
        logger.info("IoT Shodan - Exposed Device Detector")
        logger.info("Phase 2: Core Functionality ✓")
        logger.info("=" * 60)
        
        # List filters
        if args.list_filters:
            logger.info("\nAvailable predefined filters:")
            for filter_name, filter_data in PREDEFINED_FILTERS.items():
                logger.info(f"\n  {filter_name}")
                logger.info(f"    Name: {filter_data.get('name')}")
                logger.info(f"    Description: {filter_data.get('description')}")
                logger.info(f"    Query: {filter_data.get('query')}")
            return 0
        
        # Initialize Shodan client
        logger.info("\nInitializing Shodan API client...")
        client = ShodanClient(SHODAN_API_KEY)
        
        # Show account info
        if args.account_info:
            logger.info("\nFetching account information...")
            account_info = client.get_account_info()
            logger.info(f"Credits Available: {account_info['credits_available']}")
            logger.info(f"Query Credits: {account_info['query_credits']}")
            logger.info(f"Tier: {account_info['tier']}")
            return 0
        
        # Determine query
        if args.filter:
            if args.filter not in PREDEFINED_FILTERS:
                logger.error(f"Unknown filter: {args.filter}")
                logger.error("Use --list-filters to see available filters")
                return 1
            
            filter_config = PREDEFINED_FILTERS[args.filter]
            query = filter_config['query']
            logger.info(f"Using predefined filter: {args.filter}")
            logger.info(f"Filter name: {filter_config['name']}")
        
        elif args.query:
            query = args.query
            logger.info(f"Using custom query: {query}")
        
        else:
            logger.error("Please specify --filter or --query")
            parser.print_help()
            return 1
        
        # Search Shodan
        logger.info(f"\nSearching Shodan with query: {query}")
        logger.info(f"Limit: {args.limit}")
        
        results = client.search(query, limit=args.limit)
        logger.info(f"\n✓ Found {len(results['matches'])} results")
        logger.info(f"  Total available on Shodan: {results['total']}")
        
        devices = results['matches']
        
        # Vulnerability analysis
        if not args.no_analysis:
            logger.info("\nAnalyzing vulnerabilities...")
            detector = VulnerabilityDetector()
            devices = detector.analyze_batch(devices)
            
            stats = detector.get_summary_stats(devices)
            logger.info("\n" + "=" * 60)
            logger.info("VULNERABILITY ANALYSIS SUMMARY")
            logger.info("=" * 60)
            logger.info(f"Total Devices: {stats['total_devices']}")
            logger.info(f"Critical Risk (9-10): {stats['critical']}")
            logger.info(f"High Risk (7-8): {stats['high']}")
            logger.info(f"Medium Risk (5-6): {stats['medium']}")
            logger.info(f"Low Risk (1-4): {stats['low']}")
            logger.info(f"Total Vulnerabilities: {stats['total_vulnerabilities']}")
            logger.info(f"Average Risk Score: {stats['avg_risk_score']:.2f}/10")
            logger.info("=" * 60)
        
        # Generate reports
        logger.info("\nGenerating reports...")
        generator = ReportGenerator(output_dir=REPORTS_DIR)
        
        if args.format in ["json", "all"]:
            json_file = generator.generate_json(
                devices,
                query,
                filename=args.output
            )
            logger.info(f"✓ JSON report: {json_file}")
        
        if args.format in ["csv", "all"]:
            csv_file = generator.generate_csv(devices)
            logger.info(f"✓ CSV report: {csv_file}")
        
        if not args.no_analysis and args.format == "json":
            txt_file = generator.generate_summary_txt(devices, query, stats)
            logger.info(f"✓ Summary report: {txt_file}")
        
        logger.info("\n✓ Analysis complete!")
        logger.info(f"Reports saved to: {REPORTS_DIR}")
        
        return 0
        
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        return 1
    except ShodanAPIError as e:
        logger.error(f"Shodan API error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
