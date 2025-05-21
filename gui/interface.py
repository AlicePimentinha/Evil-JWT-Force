# EVIL_JWT_FORCE/gui/interface.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import sys
import os
from pathlib import Path

class ModuleDialog:
    def __init__(self, parent, title, fields):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("500x400")
        self.dialog.configure(bg="#1e1e1e")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Frame para os campos
        self.frame = tk.Frame(self.dialog, bg="#1e1e1e")
        self.frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Dicionário para armazenar as entradas
        self.entries = {}
        
        # Criar campos
        for i, (label, field_type) in enumerate(fields.items()):
            tk.Label(self.frame, text=label, bg="#1e1e1e", fg="white").grid(row=i, column=0, pady=5, sticky='w')
            
            if field_type == "entry":
                self.entries[label] = tk.Entry(self.frame, bg="#2e2e2e", fg="white", width=40)
                self.entries[label].grid(row=i, column=1, pady=5, padx=10)
            elif field_type == "file":
                frame = tk.Frame(self.frame, bg="#1e1e1e")
                frame.grid(row=i, column=1, pady=5, sticky='w')
                self.entries[label] = tk.Entry(frame, bg="#2e2e2e", fg="white", width=32)
                self.entries[label].pack(side=tk.LEFT, padx=(0,5))
                browse_btn = tk.Button(frame, text="...", command=lambda l=label: self.browse_file(l))
                browse_btn.pack(side=tk.LEFT)
            elif isinstance(field_type, list):
                self.entries[label] = ttk.Combobox(self.frame, values=field_type, width=37)
                self.entries[label].grid(row=i, column=1, pady=5, padx=10)
                self.entries[label].set(field_type[0])
        
        # Botão de iniciar
        self.start_button = tk.Button(self.dialog, text="Iniciar Ataque", 
                                    command=self.start_attack,
                                    bg="#ff3c00", fg="white",
                                    font=("Arial", 10, "bold"))
        self.start_button.pack(pady=20)

    def browse_file(self, field_label):
        filename = filedialog.askopenfilename()
        if filename:
            self.entries[field_label].delete(0, tk.END)
            self.entries[field_label].insert(0, filename)

    def start_attack(self):
        values = {label: entry.get() for label, entry in self.entries.items()}
        print("Iniciando ataque com parâmetros:", values)
        self.dialog.destroy()

class EvilJWTGUI:
    def __init__(self, master):
        self.master = master
        master.title("EVIL_JWT_FORCE")
        master.geometry("600x400")
        master.configure(bg="#1e1e1e")

        # Frame principal
        self.main_frame = tk.Frame(master, bg="#1e1e1e")
        self.main_frame.pack(expand=True, fill='both')

        # Menu manual frame
        self.manual_frame = tk.Frame(master, bg="#1e1e1e")

        # Nome do programa
        self.title_label = tk.Label(self.main_frame, text="🔥 EVIL_JWT_FORCE 🔥", 
                                  fg="orange", bg="#1e1e1e", 
                                  font=("Arial", 18, "bold"))
        self.title_label.pack(pady=20)

        # Botões do menu principal
        self.auto_button = tk.Button(self.main_frame, text="Modo Automático",
                                   command=self.run_auto_mode, width=25,
                                   bg="#444", fg="white", font=("Arial", 12))
        self.auto_button.pack(pady=10)

        self.manual_button = tk.Button(self.main_frame, text="Modo Manual",
                                     command=self.show_manual_menu, width=25,
                                     bg="#444", fg="white", font=("Arial", 12))
        self.manual_button.pack(pady=10)

        self.quit_button = tk.Button(self.main_frame, text="Sair",
                                   command=master.quit, width=25,
                                   bg="#aa0000", fg="white", font=("Arial", 12, "bold"))
        self.quit_button.pack(pady=20)

        # Configuração do menu manual
        self.setup_manual_menu()

        # Definição dos campos para cada módulo
        self.module_fields = {
            "auth.py": {
                "URL do Alvo": "entry",
                "Arquivo de Credenciais": "file",
                "Método de Autenticação": [
                    "JWT", "Basic", "Bearer", "OAuth2", "API Key",
                    "Digest", "NTLM", "Kerberos", "SAML",
                    "OpenID Connect", "HMAC", "Custom"
                ],
                "Timeout (segundos)": "entry",
                "Headers Customizados": "entry"
            },
            "wordlist_generator.py": {
                "Arquivo de Base": "file",
                "URL do Alvo": "entry",
                "Arquivo de Saída": "entry",
                "Mínimo de Caracteres": "entry",
                "Máximo de Caracteres": "entry",
                "Fontes de Dados": ["DuckDuckGo", "GitHub", "LinkedIn", "Facebook",
                                  "Twitter", "Instagram", "Reddit", "Sites .gov",
                                  "Sites .org", "Sites .edu"],
                "Profundidade de Busca": "entry",
                "Filtros Customizados": "entry"
            },
            "bruteforce.py": {
                "Tipo de Token": ["JWT", "OAuth", "Basic Auth", "Bearer", "API Key",
                                "Session Token", "SAML", "Custom Token"],
                "Token/Hash": "entry",
                "Wordlist": "file",
                "Método de Ataque": ["Força Bruta", "Dicionário", "Híbrido"],
                "Threads": "entry",
                "Timeout por Tentativa": "entry",
                "Alvo de Ataque": ["Token", "Login", "Verificação Única"]
            },
            "aes_decrypt.py": {
                "Arquivo de Tokens": "file",
                "Chave AES (opcional)": "entry",
                "Modo de Operação": ["CBC", "ECB", "CFB", "OFB"],
                "Arquivo de Saída": "entry"
            },
            "sql_injector.py": {
                "URL do Alvo": "entry",
                "Parâmetros": "entry",
                "Método": ["GET", "POST"],
                "Payload Customizado": "entry"
            },
            "sentry_simulator.py": {
                "Porta de Escuta": "entry",
                "Interface": "entry",
                "Arquivo de Log": "entry",
                "Modo de Captura": ["Passivo", "Ativo"]
            },
            "report.py": {
                "Diretório de Logs": "file",
                "Template": ["HTML", "PDF", "TXT"],
                "Arquivo de Saída": "entry"
            }
        }

    def setup_manual_menu(self):
        # Título do menu manual
        self.manual_title = tk.Label(self.manual_frame, 
                                   text="🛠️ Menu Manual 🛠️",
                                   fg="orange", bg="#1e1e1e",
                                   font=("Arial", 16, "bold"))
        self.manual_title.pack(pady=10)

        # Lista de módulos disponíveis
        self.modules = {
            "1. Autenticação": "auth.py",
            "2. Gerador de Wordlist": "wordlist_generator.py",
            "3. Força Bruta JWT": "bruteforce.py",
            "4. Descriptografia AES": "aes_decrypt.py",
            "5. Injeção SQL": "sql_injector.py",
            "6. Simulador Sentry": "sentry_simulator.py",
            "7. Gerar Relatório": "report.py"
        }

        # Criar botões para cada módulo
        for module_name, module_file in self.modules.items():
            btn = tk.Button(self.manual_frame,
                          text=module_name,
                          command=lambda m=module_file: self.run_module(m),
                          width=30,
                          bg="#444",
                          fg="white",
                          font=("Arial", 10))
            btn.pack(pady=5)

        # Botão voltar
        self.back_button = tk.Button(self.manual_frame,
                                   text="Voltar ao Menu Principal",
                                   command=self.show_main_menu,
                                   width=30,
                                   bg="#666",
                                   fg="white",
                                   font=("Arial", 10, "bold"))
        self.back_button.pack(pady=20)

    def show_manual_menu(self):
        self.main_frame.pack_forget()
        self.manual_frame.pack(expand=True, fill='both')

    def show_main_menu(self):
        self.manual_frame.pack_forget()
        self.main_frame.pack(expand=True, fill='both')

    def run_auto_mode(self):
        AutoDialog(self.master)
        self.execute_cli("--auto")

    def run_module(self, module_name):
        if module_name in self.module_fields:
            ModuleDialog(self.master, f"Configurar {module_name}", self.module_fields[module_name])
        else:
            messagebox.showerror("Erro", f"Configuração não encontrada para o módulo: {module_name}")

    def execute_cli(self, mode_flag):
        cli_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../core/cli.py"))
        if not os.path.exists(cli_path):
            messagebox.showerror("Erro", f"Arquivo CLI não encontrado: {cli_path}")
            return
        try:
            subprocess.Popen([sys.executable, cli_path, mode_flag])
            messagebox.showinfo("Execução", f"Módulo {mode_flag.replace('--', '').capitalize()} iniciado.")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao executar CLI: {e}")

class AutoDialog:
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Modo Automático")
        self.dialog.geometry("400x200")
        self.dialog.configure(bg="#1e1e1e")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Frame para os campos
        self.frame = tk.Frame(self.dialog, bg="#1e1e1e")
        self.frame.pack(expand=True, fill='both', padx=20, pady=20)
        
        # Label e campo para URL
        tk.Label(
            self.frame, 
            text="URL do Alvo:", 
            bg="#1e1e1e", 
            fg="white",
            font=("Arial", 10)
        ).pack(pady=5)
        
        self.url_entry = tk.Entry(
            self.frame,
            bg="#2e2e2e",
            fg="white",
            width=40,
            font=("Arial", 10)
        )
        self.url_entry.pack(pady=10)
        
        # Botão de iniciar ataque
        self.start_button = tk.Button(
            self.frame,
            text="Iniciar Ataque Automático",
            command=self.start_auto_attack,
            bg="#ff3c00",
            fg="white",
            font=("Arial", 10, "bold")
        )
        self.start_button.pack(pady=20)

    def start_auto_attack(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Erro", "Por favor, insira uma URL válida")
            return
        
        print(f"Iniciando ataque automático na URL: {url}")
        self.dialog.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = EvilJWTGUI(root)
    root.mainloop()
