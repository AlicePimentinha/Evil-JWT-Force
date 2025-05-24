import datetime
import json
from pathlib import Path
from typing import Dict, Any, Optional, List

from utils.logger import get_logger

logger = get_logger("EVIL_JWT_FORCE.report")

class ReportGenerator:
    def __init__(self, output_path: str = "reports/report.html"):
        self.output_path = Path(output_path)
        self.sections: List[str] = []
        self.attachments: Dict[str, str] = {}

    def add_section(self, title: str, content: str):
        self.sections.append(f"<h2>{title}</h2>\n{content}")

    def add_table(self, title: str, data: Dict[str, Any]):
        table = "<table border='1' cellpadding='5' cellspacing='0'>"
        table += "<tr><th>Item</th><th>Valor</th></tr>"
        for key, val in data.items():
            table += f"<tr><td>{key}</td><td>{val}</td></tr>"
        table += "</table>"
        self.add_section(title, table)

    def add_attachment(self, name: str, file_path: str):
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            self.attachments[name] = content
            logger.info(f"Anexo '{name}' adicionado ao relatório.")
        except Exception as e:
            logger.warning(f"Falha ao anexar '{name}': {e}")

    def build_html(self, stats: Dict[str, Any], extra: Optional[Dict[str, Any]] = None) -> str:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        html = [
            "<html>",
            "<head>",
            "<meta charset='utf-8'>",
            "<title>EVIL JWT FORCE - Relatório</title>",
            "<style>",
            "body { font-family: Arial, sans-serif; background: #181818; color: #e0e0e0; }",
            "h1, h2 { color: #ff5252; }",
            "table { background: #222; color: #e0e0e0; border-collapse: collapse; }",
            "th, td { border: 1px solid #444; padding: 6px 12px; }",
            "th { background: #333; }",
            "tr:nth-child(even) { background: #242424; }",
            "pre { background: #222; color: #e0e0e0; padding: 10px; border-radius: 4px; }",
            "</style>",
            "</head>",
            "<body>",
            "<h1>EVIL JWT FORCE - Relatório de Operações</h1>",
            f"<p><b>Data:</b> {timestamp}</p>"
        ]
        # Estatísticas principais
        self.add_table("Estatísticas Gerais", stats)
        # Seções adicionais
        html.extend(self.sections)
        # Anexos
        if self.attachments:
            html.append("<h2>Anexos</h2>")
            for name, content in self.attachments.items():
                html.append(f"<h3>{name}</h3>")
                html.append(f"<pre>{self._escape_html(content)}</pre>")
        # Dados extras (JSON)
        if extra:
            html.append("<h2>Dados Extras</h2>")
            html.append(f"<pre>{self._escape_html(json.dumps(extra, indent=2, ensure_ascii=False))}</pre>")
        html.append("</body></html>")
        return "\n".join(html)

    def generate(self, stats: Dict[str, Any], extra: Optional[Dict[str, Any]] = None):
        self.output_path.parent.mkdir(parents=True, exist_ok=True)
        html = self.build_html(stats, extra)
        self.output_path.write_text(html, encoding="utf-8")
        logger.info(f"Relatório HTML salvo em: {self.output_path}")

    @staticmethod
    def _escape_html(text: str) -> str:
        return (
            text.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
        )

def generate_report(data: dict):
    """
    Gera e salva um relatório em HTML ou JSON.
    """
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if format == "html":
        report = ReportGenerator(output_path)
        report.generate(data)
    elif format == "json":
        import json
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    else:
        raise ValueError("Formato de relatório não suportado: %s" % format)
    logger.info(f"Relatório gerado em: {output_path}")
    """
    Função utilitária para geração rápida de relatório.
    """
    stats = stats or {"Status": "Nenhuma estatística fornecida"}
    report = ReportGenerator()
    # Exemplos de anexos automáticos (credenciais, tokens, logs)
    for name, path in [
        ("Credenciais Válidas", "output/valid_credentials.txt"),
        ("Credenciais Inválidas", "output/invalid_credentials.txt"),
        ("Tokens Interceptados", "output/intercepted_tokens.txt"),
        ("Chaves Encontradas", "found_key.txt"),
    ]:
        if Path(path).exists():
            report.add_attachment(name, path)
    report.generate(stats, extra)