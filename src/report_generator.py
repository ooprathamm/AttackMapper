from jinja2 import Environment, FileSystemLoader
import os
from datetime import datetime

class ReportGenerator:
    def __init__(self, template_dir):
        self.env = Environment(loader=FileSystemLoader(template_dir))
        self.template_name = "report_template.html"

    def generate_report(self, data, output_path):
        template = self.env.get_template(self.template_name)
        
        if 'scan_date' not in data:
            data['scan_date'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        html_content = template.render(**data)
        
        with open(output_path, 'w') as f:
            f.write(html_content)
        
        print(f"-> Report generated at {output_path}")
