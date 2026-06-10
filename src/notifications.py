"""
Notification System
Sends alerts via email and webhooks for critical vulnerabilities
"""

import logging
import json
import smtplib
from pathlib import Path
from typing import Dict, List, Any, Optional
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import requests

logger = logging.getLogger(__name__)


class NotificationManager:
    """
    Manages notifications for critical vulnerabilities via email and webhooks
    """
    
    def __init__(self, config_path: Optional[Path] = None):
        """
        Initialize notification manager
        
        Args:
            config_path: Path to notification config JSON
        """
        self.config_path = config_path or Path('./config/notifications.json')
        self.config = self._load_config()
        self.email_enabled = self.config.get('email', {}).get('enabled', False)
        self.webhook_enabled = self.config.get('webhook', {}).get('enabled', False)
        
        logger.info(f"Notification manager initialized (Email: {self.email_enabled}, Webhook: {self.webhook_enabled})")
    
    def _load_config(self) -> Dict[str, Any]:
        """Load notification configuration from JSON"""
        if self.config_path.exists():
            try:
                with open(self.config_path) as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load notification config: {e}")
        
        # Default config
        return {
            'email': {'enabled': False},
            'webhook': {'enabled': False}
        }
    
    def send_critical_alert(
        self,
        devices: List[Dict[str, Any]],
        analysis_summary: Dict[str, Any]
    ) -> bool:
        """
        Send alert for critical vulnerabilities
        
        Args:
            devices: List of critical devices
            analysis_summary: Analysis summary statistics
            
        Returns:
            True if any notification was sent
        """
        if not devices:
            logger.debug("No critical devices to alert")
            return False
        
        sent = False
        
        if self.email_enabled:
            if self._send_email_alert(devices, analysis_summary):
                sent = True
        
        if self.webhook_enabled:
            if self._send_webhook_alert(devices, analysis_summary):
                sent = True
        
        return sent
    
    def _send_email_alert(
        self,
        devices: List[Dict[str, Any]],
        summary: Dict[str, Any]
    ) -> bool:
        """
        Send email notification
        
        Args:
            devices: Critical devices
            summary: Analysis summary
            
        Returns:
            True if successful
        """
        try:
            email_config = self.config.get('email', {})
            
            # Build email content
            subject = f"🚨 Critical Vulnerabilities Detected - {len(devices)} High-Risk Devices"
            
            body = self._build_email_body(devices, summary)
            
            # Create email message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = subject
            msg['From'] = email_config.get('from_addr', 'alerts@iot-shodan.local')
            msg['To'] = ', '.join(email_config.get('recipients', []))
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            smtp_server = email_config.get('smtp_server', 'localhost')
            smtp_port = email_config.get('smtp_port', 587)
            use_tls = email_config.get('use_tls', True)
            
            with smtplib.SMTP(smtp_server, smtp_port) as server:
                if use_tls:
                    server.starttls()
                
                if email_config.get('username'):
                    server.login(
                        email_config.get('username'),
                        email_config.get('password', '')
                    )
                
                server.send_message(msg)
            
            logger.info(f"Email alert sent to {len(email_config.get('recipients', []))} recipients")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    def _send_webhook_alert(
        self,
        devices: List[Dict[str, Any]],
        summary: Dict[str, Any]
    ) -> bool:
        """
        Send webhook notification
        
        Args:
            devices: Critical devices
            summary: Analysis summary
            
        Returns:
            True if successful
        """
        try:
            webhook_config = self.config.get('webhook', {})
            webhook_url = webhook_config.get('url')
            
            if not webhook_url:
                logger.warning("Webhook URL not configured")
                return False
            
            payload = {
                'alert_type': 'critical_vulnerabilities',
                'timestamp': str(datetime.now().isoformat()),
                'device_count': len(devices),
                'summary': summary,
                'devices': devices[:10]  # Top 10 critical devices
            }
            
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'IoT-Shodan/3.0'
            }
            
            # Add auth if configured
            if webhook_config.get('auth_token'):
                headers['Authorization'] = f"Bearer {webhook_config.get('auth_token')}"
            
            response = requests.post(
                webhook_url,
                json=payload,
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                logger.info(f"Webhook alert sent to {webhook_url}")
                return True
            else:
                logger.warning(f"Webhook returned status {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send webhook: {e}")
            return False
    
    def _build_email_body(
        self,
        devices: List[Dict[str, Any]],
        summary: Dict[str, Any]
    ) -> str:
        """Build email body text"""
        lines = [
            "=" * 70,
            "IoT EXPOSURE MONITOR - CRITICAL ALERT",
            "=" * 70,
            "",
            f"⚠️ {len(devices)} CRITICAL VULNERABILITIES DETECTED",
            "",
            "SUMMARY",
            "-" * 70,
            f"Critical Risk Devices: {summary.get('critical', 0)}",
            f"High Risk Devices: {summary.get('high', 0)}",
            f"Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}",
            f"Average Risk Score: {summary.get('avg_risk_score', 0):.2f}/10",
            "",
            "TOP CRITICAL DEVICES",
            "-" * 70,
        ]
        
        for i, device in enumerate(devices[:5], 1):
            lines.append(
                f"{i}. {device.get('ip')}:{device.get('port')} - "
                f"Risk: {device.get('risk_score')}/10 - "
                f"Product: {device.get('product', 'Unknown')}"
            )
        
        lines.extend([
            "",
            "IMMEDIATE ACTIONS REQUIRED",
            "-" * 70,
            "1. Review all critical risk devices",
            "2. Verify ownership of exposed assets",
            "3. Plan remediation timeline",
            "4. Update firewall rules if needed",
            "5. Document findings in incident tracking system",
            "",
            "For detailed analysis, run:",
            "python3 main.py --account-info",
            "",
            "=" * 70,
        ])
        
        return "\n".join(lines)
    
    def test_connection(self) -> Dict[str, bool]:
        """
        Test email and webhook connections
        
        Returns:
            Dict with connection test results
        """
        results = {
            'email': False,
            'webhook': False
        }
        
        if self.email_enabled:
            try:
                email_config = self.config.get('email', {})
                smtp_server = email_config.get('smtp_server', 'localhost')
                smtp_port = email_config.get('smtp_port', 587)
                
                with smtplib.SMTP(smtp_server, smtp_port, timeout=5) as server:
                    server.noop()
                
                logger.info("Email connection test: OK")
                results['email'] = True
            except Exception as e:
                logger.warning(f"Email connection test failed: {e}")
        
        if self.webhook_enabled:
            try:
                webhook_config = self.config.get('webhook', {})
                webhook_url = webhook_config.get('url')
                
                if webhook_url:
                    response = requests.head(webhook_url, timeout=5)
                    results['webhook'] = response.status_code < 500
                    logger.info(f"Webhook connection test: {response.status_code}")
            except Exception as e:
                logger.warning(f"Webhook connection test failed: {e}")
        
        return results


from datetime import datetime
