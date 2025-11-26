import subprocess
import xml.etree.ElementTree as ET
import shutil
import sys

class Scanner:
    def __init__(self):
        if not shutil.which("nmap"):
            raise EnvironmentError("Nmap is not installed or not in PATH.")

    def run_scan(self, target):
        print(f"-> Starting Nmap scan on {target}...")
        try:
            result = subprocess.run(
                ["nmap", "-sV", "-oX", "-", target],
                capture_output=True,
                text=True,
                check=True
            )
            return self.parse_xml(result.stdout)
        except subprocess.CalledProcessError as e:
            print(f"[!] Nmap scan failed: {e.stderr}")
            return []
        except Exception as e:
            print(f"[!] Error running scan: {e}")
            return []

    def parse_xml(self, xml_data):
        try:
            root = ET.fromstring(xml_data)
            services = []

            for host in root.findall("host"):
                status = host.find("status")
                if status is not None and status.get("state") != "up":
                    continue

                ports = host.find("ports")
                if ports is None:
                    continue

                for port in ports.findall("port"):
                    state = port.find("state")
                    if state is None or state.get("state") != "open":
                        continue

                    port_id = port.get("portid")
                    protocol = port.get("protocol")
                    
                    service = port.find("service")
                    service_name = "unknown"
                    product = ""
                    version = ""
                    
                    if service is not None:
                        service_name = service.get("name", "unknown")
                        product = service.get("product", "")
                        version = service.get("version", "")

                    services.append({
                        "port": port_id,
                        "protocol": protocol,
                        "name": service_name,
                        "product": product,
                        "version": version
                    })
            
            return services
        except ET.ParseError as e:
            print(f"[!] Error parsing XML: {e}")
            return []
