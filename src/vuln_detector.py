"""
Vulnerability Detector
Analyzes Shodan results for common vulnerabilities and security issues.
"""

import re
import logging
from typing import Dict, List, Any, Tuple
from config.settings import VULN_PATTERNS, RISK_SCORES

logger = logging.getLogger(__name__)


class VulnerabilityDetector:
    """
    Detects vulnerabilities in Shodan results using pattern matching and analysis.
    """
    
    def __init__(self):
        """Initialize detector with configured patterns and scores"""
        self.patterns = VULN_PATTERNS
        self.risk_scores = RISK_SCORES
        logger.info("Vulnerability detector initialized")
    
    def analyze_device(self, device: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single device for vulnerabilities
        
        Args:
            device: Device data from Shodan
            
        Returns:
            Device with added 'vulnerabilities' and 'risk_score' fields
        """
        device['vulnerabilities'] = []
        device['risk_score'] = 0
        
        # Extract analyzable data
        banner = device.get('data', '') or device.get('banner', '') or ''
        product = device.get('product', '') or ''
        version = device.get('version', '') or ''
        http_status = device.get('http', {}).get('status', None) if isinstance(device.get('http'), dict) else None
        
        # Run detectors
        self._check_default_credentials(device, banner, product)
        self._check_auth_errors(device, http_status)
        self._check_known_cves(device, product, version)
        self._check_risky_banners(device, banner)
        self._check_unencrypted_protocols(device)
        
        # Calculate risk score
        device['risk_score'] = self._calculate_risk_score(device['vulnerabilities'])
        
        return device
    
    def analyze_batch(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze multiple devices
        
        Args:
            devices: List of device data from Shodan
            
        Returns:
            List of analyzed devices with vulnerability data
        """
        logger.info(f"Analyzing {len(devices)} devices for vulnerabilities...")
        
        analyzed = []
        for i, device in enumerate(devices, 1):
            analyzed_device = self.analyze_device(device)
            analyzed.append(analyzed_device)
            
            if analyzed_device['risk_score'] >= 7:
                logger.warning(
                    f"[{i}/{len(devices)}] HIGH RISK: {device.get('ip')} "
                    f"(Score: {analyzed_device['risk_score']}, Vulns: {len(analyzed_device['vulnerabilities'])})"
                )
            elif analyzed_device['risk_score'] >= 5:
                logger.info(
                    f"[{i}/{len(devices)}] Medium risk: {device.get('ip')} "
                    f"(Score: {analyzed_device['risk_score']})"
                )
        
        return analyzed
    
    def _check_default_credentials(
        self,
        device: Dict[str, Any],
        banner: str,
        product: str
    ) -> None:
        """Check for hints of default credentials"""
        search_text = f"{banner} {product}".lower()
        
        for pattern in self.patterns.get('default_credentials', []):
            if re.search(pattern, search_text):
                device['vulnerabilities'].append({
                    'type': 'default_credentials_hint',
                    'severity': self.risk_scores.get('default_credentials', 8),
                    'evidence': f"Pattern '{pattern}' found in banner/product",
                    'recommendation': 'Change default credentials immediately'
                })
                logger.debug(f"Found default credential hint in {device.get('ip')}: {pattern}")
                break  # Avoid duplicates
    
    def _check_auth_errors(
        self,
        device: Dict[str, Any],
        http_status: int
    ) -> None:
        """Check for HTTP authentication errors (401, 403)"""
        if http_status in self.patterns.get('auth_errors', []):
            device['vulnerabilities'].append({
                'type': 'auth_error',
                'severity': self.risk_scores.get('auth_error', 6),
                'evidence': f"HTTP {http_status} (Authentication Required)",
                'recommendation': 'Verify authentication is properly configured'
            })
            logger.debug(f"Found auth error ({http_status}) in {device.get('ip')}")
    
    def _check_known_cves(
        self,
        device: Dict[str, Any],
        product: str,
        version: str
    ) -> None:
        """Check for known CVEs in product/version"""
        cves = self.patterns.get('common_cves', {})
        
        for product_name, cve_list in cves.items():
            if product_name.lower() in product.lower():
                for cve in cve_list:
                    device['vulnerabilities'].append({
                        'type': 'known_cve',
                        'severity': self.risk_scores.get('known_cve', 9),
                        'evidence': f"{cve} affects {product_name}",
                        'cve_id': cve,
                        'recommendation': f'Update {product_name} to latest version'
                    })
                    logger.debug(f"Found known CVE in {device.get('ip')}: {cve}")
    
    def _check_risky_banners(
        self,
        device: Dict[str, Any],
        banner: str
    ) -> None:
        """Check for risky keywords in banner"""
        search_text = banner.lower()
        
        for pattern in self.patterns.get('risky_banners', []):
            if re.search(pattern, search_text):
                device['vulnerabilities'].append({
                    'type': 'risky_banner',
                    'severity': self.risk_scores.get('risky_banner', 5),
                    'evidence': f"Banner contains suspicious term: '{pattern}'",
                    'recommendation': 'Review server configuration'
                })
                logger.debug(f"Found risky banner in {device.get('ip')}: {pattern}")
                break
    
    def _check_unencrypted_protocols(self, device: Dict[str, Any]) -> None:
        """Check for use of unencrypted protocols"""
        port = device.get('port', 0)
        product = (device.get('product', '') or '').lower()
        
        unencrypted = {
            21: ('FTP', 'SFTP'),
            23: ('Telnet', 'SSH'),
            80: ('HTTP', 'HTTPS'),
            3306: ('MySQL', 'MySQL with SSL'),
            27017: ('MongoDB', 'MongoDB with SSL'),
        }
        
        if port in unencrypted:
            device['vulnerabilities'].append({
                'type': 'unencrypted_protocol',
                'severity': self.risk_scores.get('unencrypted_protocol', 7),
                'evidence': f"Port {port} typically uses unencrypted protocol",
                'recommendation': f"Use encrypted alternative (e.g., {unencrypted[port][1]})",
                'port': port
            })
            logger.debug(f"Found unencrypted protocol in {device.get('ip')}: port {port}")
    
    def _calculate_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> int:
        """
        Calculate overall risk score (0-10) based on vulnerabilities
        
        Args:
            vulnerabilities: List of detected vulnerabilities
            
        Returns:
            Risk score from 0-10
        """
        if not vulnerabilities:
            return 0
        
        # Sort by severity and take the highest
        max_severity = max(v.get('severity', 0) for v in vulnerabilities)
        
        # Adjust based on number of vulnerabilities
        count_bonus = min(len(vulnerabilities) - 1, 3)  # Max +3 points
        
        score = min(max_severity + count_bonus, 10)
        
        return score
    
    def get_summary_stats(self, devices: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics for analyzed devices
        
        Args:
            devices: List of analyzed devices
            
        Returns:
            Summary statistics
        """
        total = len(devices)
        critical = sum(1 for d in devices if d.get('risk_score', 0) >= 9)
        high = sum(1 for d in devices if 7 <= d.get('risk_score', 0) < 9)
        medium = sum(1 for d in devices if 5 <= d.get('risk_score', 0) < 7)
        low = sum(1 for d in devices if 1 <= d.get('risk_score', 0) < 5)
        none = sum(1 for d in devices if d.get('risk_score', 0) == 0)
        
        total_vulns = sum(len(d.get('vulnerabilities', [])) for d in devices)
        
        return {
            'total_devices': total,
            'critical': critical,
            'high': high,
            'medium': medium,
            'low': low,
            'no_vulnerabilities': none,
            'total_vulnerabilities': total_vulns,
            'avg_vulns_per_device': total_vulns / total if total > 0 else 0,
            'avg_risk_score': sum(d.get('risk_score', 0) for d in devices) / total if total > 0 else 0
        }
    
    def export_vulnerabilities_only(self, devices: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Export only devices with vulnerabilities
        
        Args:
            devices: List of analyzed devices
            
        Returns:
            List of devices with risk_score >= 1
        """
        return [d for d in devices if d.get('risk_score', 0) >= 1]
