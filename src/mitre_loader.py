import pandas as pd
import json
import os

class MitreLoader:
    def __init__(self, excel_path, mapping_path):
        self.excel_path = excel_path
        self.mapping_path = mapping_path
        self.mitre_data = {} # ID -> {name, description, tactics, url}
        self.service_map = {} # service -> [ID, ID]

        self.load_data()

    def load_data(self):
        try:
            with open(self.mapping_path, 'r') as f:
                self.service_map = json.load(f)
        except Exception as e:
            print(f"[!] Error loading service mapping: {e}")

        try:
            if not os.path.exists(self.excel_path):
                print(f"[!] MITRE Excel file not found at {self.excel_path}")
                return

            df = pd.read_excel(self.excel_path)
            df.columns = [c.lower().strip() for c in df.columns]
            
            for _, row in df.iterrows():
                if pd.isna(row.get('id')):
                    continue
                
                tid = str(row.get('id')).strip()
                self.mitre_data[tid] = {
                    "id": tid,
                    "name": row.get('name', 'Unknown'),
                    "description": row.get('description', ''),
                    "tactics": str(row.get('tactics', '')).split(','), # Might need cleaning
                    "url": row.get('url', f"https://attack.mitre.org/techniques/{tid}")
                }
                
        except Exception as e:
            print(f"[!] Error loading MITRE Excel: {e}")

    def get_techniques_for_service(self, service_name):
        service_name = service_name.lower()
        technique_ids = self.service_map.get(service_name, self.service_map.get("unknown", []))
        
        results = []
        for tid in technique_ids:
            if tid in self.mitre_data:
                results.append(self.mitre_data[tid])
            else:
                results.append({
                    "id": tid,
                    "name": "Unknown Technique",
                    "description": "Details not found in provided Excel file.",
                    "tactics": [],
                    "url": f"https://attack.mitre.org/techniques/{tid}"
                })
        return results
