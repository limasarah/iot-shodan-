#!/usr/bin/env python3
"""
IoT Shodan - Main Entry Point
Security research tool for identifying exposed devices using Shodan API

Phase 1: Architecture & Setup (Current)
"""

import sys
import argparse
from pathlib import Path

# Add project root to path
PROJECT_ROOT = Path(__file__).parent
sys.path.insert(0, str(PROJECT_ROOT))

from config.settings import validate_config
from src.logger import setup_logger

logger = setup_logger(__name__)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="IoT Shodan - Exposed Device Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Search for RTSP cameras
  python main.py --filter cameras

  # Search with custom Shodan query
  python main.py --query "port:554" --limit 50

  # List available predefined filters
  python main.py --list-filters
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
        help="Output file path (default: reports/results.json)",
        default=None
    )
    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Output format (default: json)"
    )
    parser.add_argument(
        "--list-filters",
        action="store_true",
        help="List available predefined filters"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    try:
        # Validate configuration
        validate_config()
        logger.info("Configuration validated successfully")
        
        # Phase 1: Just show startup message
        logger.info("=" * 60)
        logger.info("IoT Shodan - Exposed Device Detector")
        logger.info("Phase 1: Architecture & Setup ✓")
        logger.info("=" * 60)
        
        if args.list_filters:
            from config.settings import PREDEFINED_FILTERS
            logger.info("\nAvailable predefined filters:")
            for filter_name, filter_data in PREDEFINED_FILTERS.items():
                logger.info(f"\n  {filter_name}")
                logger.info(f"    Name: {filter_data.get('name')}")
                logger.info(f"    Description: {filter_data.get('description')}")
                logger.info(f"    Query: {filter_data.get('query')}")
            return 0
        
        logger.info("\nCurrent Phase: Phase 1 - Architecture Setup Complete")
        logger.info("\nNext Steps:")
        logger.info("  1. Phase 2: Implement Shodan client integration")
        logger.info("  2. Phase 3: Add vulnerability detection")
        logger.info("  3. Phase 4: Generate reports")
        logger.info("\nFor now, use --list-filters to see available filters")
        logger.info("or run: python main.py --list-filters")
        
        return 0
        
    except ValueError as e:
        logger.error(f"Configuration error: {e}")
        return 1
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
