import unittest
import os
import sys
import pandas as pd
import shutil
from unittest.mock import patch, MagicMock

# Add src to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.scanner import Scanner
from src.mitre_loader import MitreLoader
from src.risk_engine import RiskEngine
from src.report_generator import ReportGenerator

class TestAttackSurfaceMapper(unittest.TestCase):
    
    @classmethod
    def setUpClass(cls):
        # Create dummy MITRE Excel
        cls.excel_path = "tests/test_mitre.xlsx"
        df = pd.DataFrame({
            'ID': ['T1190', 'T1021.004'],
            'name': ['Exploit Public-Facing Application', 'Remote Services: SSH'],
            'description': ['Exploit vuln', 'SSH access'],
            'tactics': ['Initial Access', 'Lateral Movement'],
            'url': ['http://example.com/T1190', 'http://example.com/T1021.004']
        })
        df.to_excel(cls.excel_path, index=False)
        
        # Create dummy mapping
        cls.mapping_path = "tests/test_mapping.json"
        with open(cls.mapping_path, 'w') as f:
            f.write('{"http": ["T1190"], "ssh": ["T1021.004"]}')

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.excel_path):
            os.remove(cls.excel_path)
        if os.path.exists(cls.mapping_path):
            os.remove(cls.mapping_path)
        if os.path.exists("test_report.html"):
            os.remove("test_report.html")

    def test_mitre_loader(self):
        loader = MitreLoader(self.excel_path, self.mapping_path)
        techs = loader.get_techniques_for_service("http")
        self.assertEqual(len(techs), 1)
        self.assertEqual(techs[0]['id'], 'T1190')
        self.assertEqual(techs[0]['name'], 'Exploit Public-Facing Application')

    @patch('subprocess.run')
    def test_scanner_and_full_flow(self, mock_run):
        # Mock Nmap Output
        mock_xml = """
        <nmaprun>
            <host>
                <status state="up"/>
                <ports>
                    <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache"/></port>
                    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH"/></port>
                </ports>
            </host>
        </nmaprun>
        """
        mock_run.return_value = MagicMock(stdout=mock_xml, returncode=0)
        
        # 1. Scan
        # We need to mock shutil.which to avoid error if nmap not installed in test env
        with patch('shutil.which', return_value='/usr/bin/nmap'):
            scanner = Scanner()
            services = scanner.run_scan("127.0.0.1")
        
        self.assertEqual(len(services), 2)
        self.assertEqual(services[0]['name'], 'http')
        
        # 2. Map
        loader = MitreLoader(self.excel_path, self.mapping_path)
        for s in services:
            s['techniques'] = loader.get_techniques_for_service(s['name'])
            
        self.assertTrue(len(services[0]['techniques']) > 0)
        
        # 3. Risk
        engine = RiskEngine()
        score, level = engine.calculate_risk(services)
        self.assertTrue(score > 0)
        
        # 4. Report
        template_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '../templates'))
        gen = ReportGenerator(template_dir)
        data = {
            "target": "127.0.0.1",
            "risk_score": score,
            "risk_level": level,
            "open_ports_count": len(services),
            "mapped_techniques_count": 2,
            "services": services,
            "matrix": {"Initial Access": services[0]['techniques']}
        }
        gen.generate_report(data, "test_report.html")
        self.assertTrue(os.path.exists("test_report.html"))

if __name__ == '__main__':
    unittest.main()
