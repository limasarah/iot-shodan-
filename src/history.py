"""
History Database
SQLite-based history tracking for analysis results, statistics, and trends
"""

import sqlite3
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
import json

logger = logging.getLogger(__name__)


class HistoryDatabase:
    """
    Manages SQLite database for storing analysis history, results, and statistics.
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize history database
        
        Args:
            db_path: Path to SQLite database (default: ./data/history.db)
        """
        self.db_path = db_path or Path('./data/history.db')
        self.db_path.parent.mkdir(exist_ok=True)
        
        self._init_db()
        logger.info(f"History database initialized: {self.db_path}")
    
    def _init_db(self) -> None:
        """Initialize database tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Analyses table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analyses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    query TEXT NOT NULL,
                    filter_name TEXT,
                    limit_results INTEGER,
                    total_found INTEGER,
                    devices_analyzed INTEGER,
                    execution_time_seconds FLOAT,
                    avg_risk_score FLOAT,
                    critical_count INTEGER,
                    high_count INTEGER,
                    medium_count INTEGER,
                    low_count INTEGER,
                    notes TEXT,
                    UNIQUE(timestamp, query)
                )
            ''')
            
            # Devices table (for tracking seen devices)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    product TEXT,
                    country TEXT,
                    organization TEXT,
                    risk_score INTEGER,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    times_seen INTEGER DEFAULT 1,
                    UNIQUE(ip, port)
                )
            ''')
            
            # Vulnerabilities table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER NOT NULL,
                    vuln_type TEXT NOT NULL,
                    severity INTEGER,
                    evidence TEXT,
                    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (device_id) REFERENCES devices(id)
                )
            ''')
            
            # Statistics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS statistics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    metric_name TEXT UNIQUE NOT NULL,
                    metric_value TEXT,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            logger.info("Database schema initialized")
    
    def add_analysis(
        self,
        query: str,
        filter_name: Optional[str],
        limit_results: int,
        total_found: int,
        devices_analyzed: int,
        execution_time: float,
        stats: Dict[str, Any],
        notes: Optional[str] = None
    ) -> int:
        """
        Record a new analysis in history
        
        Args:
            query: Shodan query used
            filter_name: Filter name if used
            limit_results: Limit parameter
            total_found: Total results on Shodan
            devices_analyzed: Devices actually analyzed
            execution_time: Execution time in seconds
            stats: Statistics dict from vulnerability detector
            notes: Optional notes
            
        Returns:
            Analysis ID
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                cursor.execute('''
                    INSERT INTO analyses (
                        query, filter_name, limit_results, total_found,
                        devices_analyzed, execution_time_seconds,
                        avg_risk_score, critical_count, high_count,
                        medium_count, low_count, notes
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    query,
                    filter_name,
                    limit_results,
                    total_found,
                    devices_analyzed,
                    execution_time,
                    stats.get('avg_risk_score', 0),
                    stats.get('critical', 0),
                    stats.get('high', 0),
                    stats.get('medium', 0),
                    stats.get('low', 0),
                    notes
                ))
                
                conn.commit()
                analysis_id = cursor.lastrowid
                logger.info(f"Analysis #{analysis_id} recorded")
                return analysis_id
                
        except sqlite3.IntegrityError:
            logger.warning(f"Duplicate analysis for query: {query}")
            return -1
    
    def add_device(
        self,
        ip: str,
        port: int,
        product: str,
        country: str,
        organization: str,
        risk_score: int
    ) -> int:
        """
        Add or update device in history
        
        Args:
            ip: IP address
            port: Port number
            product: Product name
            country: Country
            organization: Organization name
            risk_score: Risk score (0-10)
            
        Returns:
            Device ID
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Try to update
                cursor.execute('''
                    UPDATE devices
                    SET last_seen = CURRENT_TIMESTAMP,
                        times_seen = times_seen + 1,
                        risk_score = MAX(risk_score, ?)
                    WHERE ip = ? AND port = ?
                ''', (risk_score, ip, port))
                
                if cursor.rowcount > 0:
                    # Device updated
                    cursor.execute('''
                        SELECT id FROM devices WHERE ip = ? AND port = ?
                    ''', (ip, port))
                    return cursor.fetchone()[0]
                else:
                    # Insert new device
                    cursor.execute('''
                        INSERT INTO devices (
                            ip, port, product, country,
                            organization, risk_score
                        ) VALUES (?, ?, ?, ?, ?, ?)
                    ''', (ip, port, product, country, organization, risk_score))
                    
                    conn.commit()
                    return cursor.lastrowid
                    
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
            return -1
    
    def get_analysis_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent analysis history
        
        Args:
            limit: Number of recent analyses to return
            
        Returns:
            List of analysis records
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM analyses
                    ORDER BY timestamp DESC
                    LIMIT ?
                ''', (limit,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            logger.error(f"Query error: {e}")
            return []
    
    def get_high_risk_devices(self, risk_threshold: int = 7) -> List[Dict[str, Any]]:
        """
        Get devices with high risk scores
        
        Args:
            risk_threshold: Minimum risk score (default: 7)
            
        Returns:
            List of high-risk devices
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                cursor.execute('''
                    SELECT * FROM devices
                    WHERE risk_score >= ?
                    ORDER BY risk_score DESC, times_seen DESC
                ''', (risk_threshold,))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            logger.error(f"Query error: {e}")
            return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get overall statistics from history
        
        Returns:
            Dictionary with statistics
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Total analyses
                cursor.execute('SELECT COUNT(*) FROM analyses')
                total_analyses = cursor.fetchone()[0]
                
                # Total unique devices
                cursor.execute('SELECT COUNT(*) FROM devices')
                total_devices = cursor.fetchone()[0]
                
                # Average risk score
                cursor.execute('SELECT AVG(risk_score) FROM devices')
                avg_risk = cursor.fetchone()[0] or 0
                
                # High risk devices
                cursor.execute('SELECT COUNT(*) FROM devices WHERE risk_score >= 7')
                high_risk = cursor.fetchone()[0]
                
                # Most seen devices
                cursor.execute('''
                    SELECT ip, port, times_seen FROM devices
                    ORDER BY times_seen DESC LIMIT 5
                ''')
                top_devices = cursor.fetchall()
                
                return {
                    'total_analyses': total_analyses,
                    'total_unique_devices': total_devices,
                    'average_risk_score': round(avg_risk, 2),
                    'high_risk_count': high_risk,
                    'most_seen_devices': [
                        {'ip': ip, 'port': port, 'times': times}
                        for ip, port, times in top_devices
                    ]
                }
                
        except sqlite3.Error as e:
            logger.error(f"Query error: {e}")
            return {}
    
    def search_devices(self, query: str) -> List[Dict[str, Any]]:
        """
        Search devices by IP, product, or organization
        
        Args:
            query: Search query
            
        Returns:
            Matching devices
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                search_pattern = f"%{query}%"
                cursor.execute('''
                    SELECT * FROM devices
                    WHERE ip LIKE ? OR product LIKE ? OR organization LIKE ?
                    ORDER BY risk_score DESC
                ''', (search_pattern, search_pattern, search_pattern))
                
                return [dict(row) for row in cursor.fetchall()]
                
        except sqlite3.Error as e:
            logger.error(f"Search error: {e}")
            return []
    
    def export_csv(self, output_path: Path) -> bool:
        """
        Export high-risk devices to CSV
        
        Args:
            output_path: Path to save CSV
            
        Returns:
            True if successful
        """
        try:
            import csv
            
            devices = self.get_high_risk_devices(risk_threshold=0)
            
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=['ip', 'port', 'product', 'country', 'organization', 'risk_score', 'times_seen']
                )
                writer.writeheader()
                writer.writerows(devices)
            
            logger.info(f"Exported {len(devices)} devices to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Export error: {e}")
            return False
