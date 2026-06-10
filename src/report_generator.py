"""
Report Generator
Exports analyzed device data to JSON and CSV formats with professional formatting.
"""

import json
import csv
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates reports from analyzed device data in multiple formats.
    """
    
    def __init__(self, output_dir: Optional[Path] = None):
        """
        Initialize report generator
        
        Args:
            output_dir: Directory to save reports (defaults to ./reports)
        """
        self.output_dir = output_dir or Path('./reports')
        self.output_dir.mkdir(exist_ok=True)
        logger.info(f"Report generator initialized with output dir: {self.output_dir}")
    
    def generate_json(
        self,
        devices: List[Dict[str, Any]],
        query: str,
        filename: Optional[str] = None,
        include_metadata: bool = True
    ) -> Path:
        """
        Generate JSON report
        
        Args:
            devices: List of analyzed devices
            query: Shodan query used
            filename: Output filename (auto-generated if None)
            include_metadata: Whether to include metadata
            
        Returns:
            Path to generated file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.json"
        
        output_path = self.output_dir / filename
        
        report = self._build_report(devices, query) if include_metadata else {'devices': devices}
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            logger.info(f"JSON report saved to {output_path}")
            return output_path
            
        except IOError as e:
            logger.error(f"Failed to write JSON report: {e}")
            raise
    
    def generate_csv(
        self,
        devices: List[Dict[str, Any]],
        filename: Optional[str] = None,
        include_vulnerabilities: bool = True
    ) -> Path:
        """
        Generate CSV report
        
        Args:
            devices: List of analyzed devices
            filename: Output filename (auto-generated if None)
            include_vulnerabilities: Whether to include vulnerability details
            
        Returns:
            Path to generated file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{timestamp}.csv"
        
        output_path = self.output_dir / filename
        
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                if include_vulnerabilities:
                    self._write_csv_with_vulns(devices, f)
                else:
                    self._write_csv_devices(devices, f)
            
            logger.info(f"CSV report saved to {output_path}")
            return output_path
            
        except IOError as e:
            logger.error(f"Failed to write CSV report: {e}")
            raise
    
    def generate_summary_txt(
        self,
        devices: List[Dict[str, Any]],
        query: str,
        stats: Dict[str, Any],
        filename: Optional[str] = None
    ) -> Path:
        """
        Generate a text summary report
        
        Args:
            devices: List of analyzed devices
            query: Shodan query used
            stats: Statistics from vulnerability detector
            filename: Output filename
            
        Returns:
            Path to generated file
        """
        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"summary_{timestamp}.txt"
        
        output_path = self.output_dir / filename
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(self._build_text_summary(devices, query, stats))
            
            logger.info(f"Summary report saved to {output_path}")
            return output_path
            
        except IOError as e:
            logger.error(f"Failed to write summary report: {e}")
            raise
    
    def _build_report(
        self,
        devices: List[Dict[str, Any]],
        query: str
    ) -> Dict[str, Any]:
        """Build complete JSON report with metadata"""
        
        # Calculate statistics
        total = len(devices)
        critical = sum(1 for d in devices if d.get('risk_score', 0) >= 9)
        high = sum(1 for d in devices if 7 <= d.get('risk_score', 0) < 9)
        medium = sum(1 for d in devices if 5 <= d.get('risk_score', 0) < 7)
        low = sum(1 for d in devices if 1 <= d.get('risk_score', 0) < 5)
        
        return {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'query': query,
                'total_devices': total,
                'exported_devices': len(devices)
            },
            'summary': {
                'critical_vulnerabilities': critical,
                'high_risk_devices': high,
                'medium_risk_devices': medium,
                'low_risk_devices': low,
                'total_risk_score': sum(d.get('risk_score', 0) for d in devices),
                'average_risk_score': sum(d.get('risk_score', 0) for d in devices) / total if total > 0 else 0
            },
            'devices': devices
        }
    
    def _write_csv_devices(
        self,
        devices: List[Dict[str, Any]],
        file_obj
    ) -> None:
        """Write basic device CSV without vulnerability details"""
        
        fieldnames = [
            'ip',
            'port',
            'product',
            'version',
            'country',
            'org',
            'risk_score',
            'vulnerability_count'
        ]
        
        writer = csv.DictWriter(file_obj, fieldnames=fieldnames)
        writer.writeheader()
        
        for device in devices:
            writer.writerow({
                'ip': device.get('ip', 'N/A'),
                'port': device.get('port', 'N/A'),
                'product': device.get('product', 'N/A'),
                'version': device.get('version', 'N/A'),
                'country': device.get('country', 'N/A'),
                'org': device.get('org', 'N/A'),
                'risk_score': device.get('risk_score', 0),
                'vulnerability_count': len(device.get('vulnerabilities', []))
            })
    
    def _write_csv_with_vulns(
        self,
        devices: List[Dict[str, Any]],
        file_obj
    ) -> None:
        """Write device CSV with vulnerability details (one row per vulnerability)"""
        
        fieldnames = [
            'ip',
            'port',
            'product',
            'risk_score',
            'vulnerability_type',
            'severity',
            'evidence',
            'recommendation'
        ]
        
        writer = csv.DictWriter(file_obj, fieldnames=fieldnames)
        writer.writeheader()
        
        for device in devices:
            vulns = device.get('vulnerabilities', [])
            
            if vulns:
                # One row per vulnerability
                for vuln in vulns:
                    writer.writerow({
                        'ip': device.get('ip', 'N/A'),
                        'port': device.get('port', 'N/A'),
                        'product': device.get('product', 'N/A'),
                        'risk_score': device.get('risk_score', 0),
                        'vulnerability_type': vuln.get('type', 'unknown'),
                        'severity': vuln.get('severity', 'N/A'),
                        'evidence': vuln.get('evidence', ''),
                        'recommendation': vuln.get('recommendation', '')
                    })
            else:
                # Device with no vulnerabilities
                writer.writerow({
                    'ip': device.get('ip', 'N/A'),
                    'port': device.get('port', 'N/A'),
                    'product': device.get('product', 'N/A'),
                    'risk_score': 0,
                    'vulnerability_type': 'None',
                    'severity': 'N/A',
                    'evidence': 'No vulnerabilities detected',
                    'recommendation': 'N/A'
                })
    
    def _build_text_summary(
        self,
        devices: List[Dict[str, Any]],
        query: str,
        stats: Dict[str, Any]
    ) -> str:
        """Build text summary"""
        
        lines = [
            "=" * 70,
            "IoT EXPOSURE MONITOR - VULNERABILITY REPORT SUMMARY",
            "=" * 70,
            "",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Query: {query}",
            "",
            "STATISTICS",
            "-" * 70,
            f"Total Devices: {stats.get('total_devices', 0)}",
            f"Critical Risk: {stats.get('critical', 0)} devices",
            f"High Risk: {stats.get('high', 0)} devices",
            f"Medium Risk: {stats.get('medium', 0)} devices",
            f"Low Risk: {stats.get('low', 0)} devices",
            f"Total Vulnerabilities Found: {stats.get('total_vulnerabilities', 0)}",
            f"Average Risk Score: {stats.get('avg_risk_score', 0):.2f}/10",
            "",
            "TOP RISK DEVICES",
            "-" * 70,
        ]
        
        # Sort by risk score and show top 10
        top_devices = sorted(
            devices,
            key=lambda d: d.get('risk_score', 0),
            reverse=True
        )[:10]
        
        for device in top_devices:
            lines.append(
                f"  {device.get('ip')}:{device.get('port')} - "
                f"Risk Score: {device.get('risk_score')}/10 - "
                f"Vulnerabilities: {len(device.get('vulnerabilities', []))}"
            )
        
        lines.extend([
            "",
            "RECOMMENDATIONS",
            "-" * 70,
            "1. Review critical risk devices immediately",
            "2. Update products with known CVEs",
            "3. Change default credentials",
            "4. Enable encryption for sensitive protocols",
            "5. Implement network segmentation",
            "",
            "=" * 70,
        ])
        
        return "\n".join(lines)
