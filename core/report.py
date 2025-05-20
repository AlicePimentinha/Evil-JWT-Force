# utils/report.py

import datetime
from pathlib import Path

class ReportGenerator:
    def __init__(self, output_path="reports/report.html"):
        self.output_path = Path(output_path)

    def generate(self, stats: dict):
        html = self.build_html(stats)
        self.output_path.write_text(html)

    def build_html(self, stats: dict) -> str:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html = f"""<html>
<head><title>EVIL JWT FORCE - Relatório</title></head>
<body>
<h1>EVIL JWT FORCE - Relatório de Operações</h1>
<p><b>Data:</b> {timestamp}</p>
<table border="1" cellpadding="5" cellspacing="0">
<tr><th>Item</th><th>Valor</th></tr>
"""
        for key, val in stats.items():
            html += f"<tr><td>{key}</td><td>{val}</td></tr>\n"
        html += "</table></body></html>"
        return html
