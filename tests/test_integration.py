"""
Integration Tests for IoT Shodan
Tests the complete workflow with mocked Shodan API responses
"""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime

from src.shodan_client import ShodanClient, ShodanAPIError, RateLimiter
from src.vuln_detector import VulnerabilityDetector
from src.report_generator import ReportGenerator


class TestRateLimiter:
    """Test rate limiting functionality"""
    
    def test_rate_limiter_allows_first_call(self):
        """First call should not wait"""
        limiter = RateLimiter(calls_per_minute=1)
        limiter.wait_if_needed()
        assert len(limiter.call_times) == 1
    
    def test_rate_limiter_enforces_limit(self):
        """Should block when limit exceeded"""
        limiter = RateLimiter(calls_per_minute=1)
        # Simulate multiple calls
        for _ in range(2):
            limiter.wait_if_needed()
        assert len(limiter.call_times) == 2


class TestShodanClient:
    """Test Shodan API client"""
    
    @pytest.fixture
    def mock_client(self):
        """Create mock Shodan client"""
        with patch('src.shodan_client.shodan.Shodan'):
            client = ShodanClient("dummy_api_key")
            client.api = MagicMock()
            return client
    
    def test_client_initialization(self):
        """Should initialize client with valid API key"""
        with patch('src.shodan_client.shodan.Shodan') as mock_shodan:
            client = ShodanClient("valid_key")
            assert client.api_key == "valid_key"
            mock_shodan.assert_called_once_with("valid_key")
    
    def test_invalid_api_key(self):
        """Should raise error for invalid API key"""
        with patch('src.shodan_client.shodan.Shodan', side_effect=Exception("Invalid API key")):
            with pytest.raises(ShodanAPIError):
                ShodanClient("invalid_key")
    
    def test_query_validation(self, mock_client):
        """Should validate queries"""
        assert mock_client._validate_query("port:554") is True
        assert mock_client._validate_query("") is False
        assert mock_client._validate_query(None) is False
    
    def test_ip_validation(self):
        """Should validate IP addresses"""
        assert ShodanClient._validate_ip("192.168.1.1") is True
        assert ShodanClient._validate_ip("256.1.1.1") is False
        assert ShodanClient._validate_ip("invalid") is False
    
    def test_search_success(self, mock_client):
        """Should return search results"""
        mock_client.api.search.return_value = {
            'matches': [{'ip': '192.168.1.1', 'port': 554}],
            'total': 100
        }
        
        result = mock_client.search("port:554", limit=10)
        
        assert len(result['matches']) == 1
        assert result['total'] == 100
        assert result['query'] == "port:554"
    
    def test_search_error_handling(self, mock_client):
        """Should handle search errors"""
        import shodan
        mock_client.api.search.side_effect = shodan.APIError("API Error")
        
        with pytest.raises(ShodanAPIError):
            mock_client.search("port:554")
    
    def test_query_builder(self, mock_client):
        """Should build valid queries"""
        query = mock_client.build_query(port=554, product="Camera")
        assert "port:554" in query
        assert 'product:"Camera"' in query
    
    def test_host_details(self, mock_client):
        """Should fetch host details"""
        mock_client.api.host.return_value = {
            'ip_str': '192.168.1.1',
            'ports': [554, 80],
            'org': 'ISP Corp',
            'country_name': 'BR'
        }
        
        result = mock_client.get_host_details('192.168.1.1')
        
        assert result['ip'] == '192.168.1.1'
        assert 554 in result['ports']


class TestVulnerabilityDetector:
    """Test vulnerability detection"""
    
    @pytest.fixture
    def detector(self):
        """Create vulnerability detector"""
        return VulnerabilityDetector()
    
    def test_detector_initialization(self, detector):
        """Should initialize with patterns"""
        assert detector.patterns is not None
        assert 'default_credentials' in detector.patterns
    
    def test_detect_default_credentials(self, detector):
        """Should detect default credential hints"""
        device = {
            'ip': '192.168.1.1',
            'port': 554,
            'data': 'admin login required',
            'product': 'Camera'
        }
        
        result = detector.analyze_device(device)
        
        assert len(result['vulnerabilities']) > 0
        assert any(v['type'] == 'default_credentials_hint' for v in result['vulnerabilities'])
    
    def test_detect_auth_errors(self, detector):
        """Should detect HTTP auth errors"""
        device = {
            'ip': '192.168.1.1',
            'port': 80,
            'http': {'status': 401},
            'product': 'Server'
        }
        
        result = detector.analyze_device(device)
        
        assert len(result['vulnerabilities']) > 0
    
    def test_risk_score_calculation(self, detector):
        """Should calculate risk scores correctly"""
        device = {
            'ip': '192.168.1.1',
            'port': 554,
            'data': 'admin default password',
            'product': 'Hikvision'
        }
        
        result = detector.analyze_device(device)
        
        assert result['risk_score'] > 0
        assert result['risk_score'] <= 10
    
    def test_batch_analysis(self, detector):
        """Should analyze multiple devices"""
        devices = [
            {'ip': '192.168.1.1', 'port': 554, 'data': 'admin', 'product': 'Camera'},
            {'ip': '192.168.1.2', 'port': 80, 'data': 'safe', 'product': 'Server'},
        ]
        
        results = detector.analyze_batch(devices)
        
        assert len(results) == 2
        assert all('risk_score' in d for d in results)
    
    def test_summary_stats(self, detector):
        """Should generate summary statistics"""
        devices = [
            {'ip': '192.168.1.1', 'risk_score': 9, 'vulnerabilities': [{'severity': 9}]},
            {'ip': '192.168.1.2', 'risk_score': 5, 'vulnerabilities': [{'severity': 5}]},
            {'ip': '192.168.1.3', 'risk_score': 0, 'vulnerabilities': []},
        ]
        
        stats = detector.get_summary_stats(devices)
        
        assert stats['total_devices'] == 3
        assert stats['critical'] == 1
        assert stats['medium'] == 1
        assert stats['total_vulnerabilities'] == 2
    
    def test_export_vulnerabilities_only(self, detector):
        """Should filter devices by risk score"""
        devices = [
            {'ip': '192.168.1.1', 'risk_score': 9},
            {'ip': '192.168.1.2', 'risk_score': 0},
            {'ip': '192.168.1.3', 'risk_score': 6},
        ]
        
        filtered = detector.export_vulnerabilities_only(devices)
        
        assert len(filtered) == 2
        assert all(d['risk_score'] >= 1 for d in filtered)


class TestReportGenerator:
    """Test report generation"""
    
    @pytest.fixture
    def generator(self, tmp_path):
        """Create report generator with temp directory"""
        return ReportGenerator(output_dir=tmp_path)
    
    @pytest.fixture
    def sample_devices(self):
        """Sample device data"""
        return [
            {
                'ip': '192.168.1.1',
                'port': 554,
                'product': 'Hikvision Camera',
                'version': '5.4.0',
                'country': 'BR',
                'org': 'ISP Corp',
                'risk_score': 8,
                'vulnerabilities': [
                    {
                        'type': 'default_credentials_hint',
                        'severity': 8,
                        'evidence': 'Banner contains admin'
                    }
                ]
            },
            {
                'ip': '192.168.1.2',
                'port': 80,
                'product': 'Web Server',
                'version': '1.0',
                'country': 'BR',
                'org': 'ISP Corp',
                'risk_score': 0,
                'vulnerabilities': []
            }
        ]
    
    def test_json_generation(self, generator, sample_devices, tmp_path):
        """Should generate valid JSON report"""
        path = generator.generate_json(sample_devices, "port:554", filename="test.json")
        
        assert path.exists()
        with open(path) as f:
            data = json.load(f)
        
        assert 'metadata' in data
        assert 'summary' in data
        assert 'devices' in data
        assert len(data['devices']) == 2
    
    def test_csv_generation(self, generator, sample_devices):
        """Should generate valid CSV report"""
        path = generator.generate_csv(sample_devices, filename="test.csv")
        
        assert path.exists()
        with open(path) as f:
            lines = f.readlines()
        
        assert len(lines) > 1  # Header + rows
    
    def test_summary_txt_generation(self, generator, sample_devices):
        """Should generate text summary"""
        stats = {
            'total_devices': 2,
            'critical': 0,
            'high': 1,
            'medium': 0,
            'low': 0,
            'total_vulnerabilities': 1,
            'avg_risk_score': 4.0
        }
        
        path = generator.generate_summary_txt(
            sample_devices,
            "port:554",
            stats,
            filename="summary.txt"
        )
        
        assert path.exists()
        content = path.read_text()
        
        assert "VULNERABILITY REPORT" in content
        assert "192.168.1.1" in content
    
    def test_output_directory_creation(self, tmp_path):
        """Should create output directory if needed"""
        new_dir = tmp_path / "new_reports"
        assert not new_dir.exists()
        
        generator = ReportGenerator(output_dir=new_dir)
        
        assert new_dir.exists()


class TestEndToEnd:
    """End-to-end workflow tests"""
    
    @pytest.fixture
    def workflow_setup(self, tmp_path):
        """Setup complete workflow"""
        with patch('src.shodan_client.shodan.Shodan') as mock_shodan:
            client = ShodanClient("test_key")
            client.api = MagicMock()
            detector = VulnerabilityDetector()
            generator = ReportGenerator(output_dir=tmp_path)
            
            yield {
                'client': client,
                'detector': detector,
                'generator': generator,
                'api_mock': client.api,
                'tmp_path': tmp_path
            }
    
    def test_complete_workflow(self, workflow_setup):
        """Should complete full search-detect-report workflow"""
        setup = workflow_setup
        
        # Mock search results
        setup['api_mock'].search.return_value = {
            'matches': [
                {
                    'ip': '192.168.1.1',
                    'port': 554,
                    'product': 'Hikvision Camera',
                    'data': 'admin login required',
                    'http': {'status': 200}
                }
            ],
            'total': 1
        }
        
        # Step 1: Search
        results = setup['client'].search("port:554")
        assert len(results['matches']) == 1
        
        # Step 2: Analyze
        analyzed = setup['detector'].analyze_batch(results['matches'])
        assert analyzed[0]['risk_score'] > 0
        
        # Step 3: Generate report
        report_path = setup['generator'].generate_json(
            analyzed,
            "port:554",
            filename="workflow_test.json"
        )
        assert report_path.exists()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
