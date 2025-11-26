import argparse
import os
import sys
from src.scanner import Scanner
from src.mitre_loader import MitreLoader
from src.risk_engine import RiskEngine
from src.report_generator import ReportGenerator

def main():
    parser = argparse.ArgumentParser(description="Attack Surface Mapping Tool")
    parser.add_argument("--target", required=True, help="Target IP or Hostname")
    parser.add_argument("--output", default="report.html", help="Output HTML file path")
    parser.add_argument("--mitre", default="data/enterprise-attack-v18.1.xlsx", help="Path to MITRE ATT&CK Excel file")
    parser.add_argument("--mapping", default="data/service_mapping.json", help="Path to Service Mapping JSON")
    
    args = parser.parse_args()

    # 1. Initialize Components
    print("-> Initializing components...")
    try:
        scanner = Scanner()
        mitre_loader = MitreLoader(args.mitre, args.mapping)
        risk_engine = RiskEngine()
        report_generator = ReportGenerator("templates")
    except Exception as e:
        print(f"[!] Initialization failed: {e}")
        sys.exit(1)

    # 2. Run Scan
    services = scanner.run_scan(args.target)
    if not services:
        print("[!] No services found or scan failed.")
        sys.exit(1)
    
    print(f"-> Found {len(services)} open ports.")

    # 3. Map to MITRE
    print("-> Mapping services to MITRE ATT&CK...")
    matrix = {} 
    
    for service in services:
        techniques = mitre_loader.get_techniques_for_service(service['name'])
        service['techniques'] = techniques
        
        for tech in techniques:
            raw_tactics = tech.get('tactics', [])
            if isinstance(raw_tactics, str):
                raw_tactics = [t.strip() for t in raw_tactics.split(',')]
                
            for tactic in raw_tactics:
                tactic = tactic.strip()
                if not tactic: continue
                
                if tactic not in matrix:
                    matrix[tactic] = []
                
                if not any(t['id'] == tech['id'] for t in matrix[tactic]):
                    matrix[tactic].append(tech)

    # 4. Calculate Risk
    print("-> Calculating risk score...")
    risk_score, risk_level = risk_engine.calculate_risk(services)

    # 5. Generate Report
    print("-> Generating report...")
    report_data = {
        "target": args.target,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "open_ports_count": len(services),
        "mapped_techniques_count": sum(len(s['techniques']) for s in services),
        "services": services,
        "matrix": matrix
    }
    
    report_generator.generate_report(report_data, args.output)
    print("-> Done!")

if __name__ == "__main__":
    main()
