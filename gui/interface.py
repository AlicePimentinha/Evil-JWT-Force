# EVIL_JWT_FORCE/gui/interface.py
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import subprocess
import tempfile
import json
import os
from pathlib import Path
from datetime import datetime
from PIL import Image, ImageTk

class ModuleDialog:
    def __init__(self, parent, module_file, fields, custom_title=None):
        self.dialog = tk.Toplevel(parent)
        # Definir o ícone do dialog
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        icon_path = os.path.join(assets_dir, "icon.ico")
        if os.path.exists(icon_path):
            self.dialog.iconbitmap(icon_path)
        display_title = custom_title if custom_title else module_file
        self.dialog.title(display_title)
        self.dialog.state('zoomed')
        self.dialog.configure(bg="#1e1e1e")
        self.dialog.transient(parent)
        self.dialog.grab_set()

        # Título centralizado e grande, sem "Configurar" e sem número
        self.title_label = tk.Label(
            self.dialog,
            text=display_title,
            fg="#b00a0a",
            bg="#1e1e1e",
            font=("Arial", 60, "bold")
        )
        self.title_label.pack(pady=(40, 40), anchor='center')

        # Frame centralizador dos campos
        self.central_frame = tk.Frame(self.dialog, bg="#1e1e1e")
        self.central_frame.pack(expand=True, fill='both', padx=int(self.dialog.winfo_screenwidth()*0.18), pady=20)

        self.fields_frame = tk.Frame(self.central_frame, bg="#1e1e1e")
        self.fields_frame.pack(fill='x', expand=True)

        self.fields_frame.grid_columnconfigure(0, weight=1)
        self.fields_frame.grid_columnconfigure(1, weight=3)

        self.entries = {}
        row = 0
        for label, field_type in fields.items():
            # Não pule o campo "Payload Customizado", apenas trate ele corretamente
            tk.Label(
                self.fields_frame,
                text=label,
                bg="#1e1e1e",
                fg="white",
                anchor="e"
            ).grid(row=row, column=0, pady=8, padx=(0, 10), sticky='e')

            if field_type == "entry":
                self.entries[label] = tk.Entry(
                    self.fields_frame,
                    bg="#2e2e2e",
                    fg="white",
                    justify="left"
                )
                self.entries[label].grid(row=row, column=1, pady=8, sticky='ew')
            elif field_type == "file":
                frame = tk.Frame(self.fields_frame, bg="#1e1e1e")
                frame.grid(row=row, column=1, pady=8, sticky='ew')
                frame.grid_columnconfigure(0, weight=1)
                self.entries[label] = tk.Entry(
                    frame,
                    bg="#2e2e2e",
                    fg="white",
                    justify="left"
                )
                self.entries[label].grid(row=0, column=0, sticky='ew')
                browse_btn = tk.Button(frame, text="...", command=lambda l=label: self.browse_file(l))
                browse_btn.grid(row=0, column=1, padx=(5,0))
            elif isinstance(field_type, list):
                self.entries[label] = ttk.Combobox(
                    self.fields_frame,
                    values=field_type,
                    justify="left"
                )
                self.entries[label].grid(row=row, column=1, pady=8, sticky='ew')
                self.entries[label].set(field_type[0])
                if label == "Tipo de Payload":
                    self.entries[label].bind('<<ComboboxSelected>>', self.update_payload_list)
                    self.payload_listbox = tk.Listbox(
                        self.fields_frame,
                        bg="#2e2e2e",
                        fg="white",
                        height=5,
                        justify="left"
                    )
                    self.payload_listbox.grid(row=row+1, column=0, columnspan=2, pady=8, padx=0, sticky='ew')
                    row += 1
            row += 1

        # Espaçador para subir os botões e garantir espaço inferior
        self.spacer = tk.Frame(self.central_frame, height=60, bg="#1e1e1e")
        self.spacer.pack()

        self.action_frame = tk.Frame(self.central_frame, bg="#1e1e1e")
        self.action_frame.pack(anchor='center', pady=(0, 0), fill='x')

        # Define o texto do botão conforme o módulo
        button_text_map = {
            "auth.py": "Autenticar",
            "wordlist_generator.py": "Gerar",
            "bruteforce.py": "Forçar",
            "aes_decrypt.py": "Descriptografar",
            "sql_injector.py": "Injetar",
            "sentry_simulator.py": "Simular",
            "report.py": "Gerar"
        }
        start_btn_text = button_text_map.get(module_file, "Iniciar Ataque")

        self.start_button = tk.Button(
            self.action_frame,
            text=start_btn_text,
            command=self.start_attack,
            bg="#b00a0a",
            fg="white",
            font=("Arial", 32, "bold"),
            height=1,
            width=18,
            activebackground="#b00a0a", activeforeground="white", relief="flat"
        )
        self.start_button.pack(anchor='center', pady=(0, 24))

        self.close_button = tk.Button(
            self.action_frame,
            text="Fechar",
            command=self.dialog.destroy,
            bg="#444444",
            fg="white",
            font=("Arial", 18, "bold"),
            width=14,
            activebackground="#444444", activeforeground="white", relief="flat"
        )
        self.close_button.pack(anchor='center', pady=(0, 0))
        # Espaçador invisível para garantir pelo menos 200px até o final da janela
        self.bottom_spacer = tk.Frame(self.central_frame, height=200, bg="#1e1e1e")
        self.bottom_spacer.pack()


    def browse_file(self, label):
        file_path = filedialog.askopenfilename()
        if file_path:
            self.entries[label].delete(0, tk.END)
            self.entries[label].insert(0, file_path)

    def update_payload_list(self, event=None):
        if hasattr(self, 'payload_listbox'):
            self.payload_listbox.delete(0, tk.END)
            selected_type = self.entries["Tipo de Payload"].get()
            if selected_type in self.sql_payloads:
                for payload in self.sql_payloads[selected_type]:
                    self.payload_listbox.insert(tk.END, payload)

    def start_attack(self):
        values = {label: entry.get() for label, entry in self.entries.items()}
        if "Tipo de Payload" in values and hasattr(self, 'payload_listbox'):
            selected_indices = self.payload_listbox.curselection()
            if selected_indices:
                selected_payload = self.payload_listbox.get(selected_indices[0])
                values["Payload Selecionado"] = selected_payload
        self.save_config(values)

        # Salva os parâmetros em um arquivo temporário para passar ao subprocesso
        temp = tempfile.NamedTemporaryFile(delete=False, suffix=".json", mode="w", encoding="utf-8")
        json.dump(values, temp, ensure_ascii=False, indent=2)
        temp.close()

        # Mapeia o script correspondente ao módulo
        script_map = {
            "auth.py": "core/auth.py",
            "wordlist_generator.py": "core/wordlist_generator.py",
            "bruteforce.py": "core/bruteforce.py",
            "aes_decrypt.py": "core/aes_decrypt.py",
            "sql_injector.py": "core/sql_injector.py",
            "sentry_simulator.py": "core/sentry_simulator.py",
            "report.py": "core/report.py",
            "novo_modulo.py": "core/novo_modulo.py"
        }
        script_path = script_map.get(self.module_file, None)
        if script_path:
            # Abre um terminal do Windows e executa o script, mostrando a saída em tempo real
            cmd = f'start cmd /k python "{script_path}" --config "{temp.name}"'
            os.system(cmd)
        else:
            messagebox.showinfo("Ação", f"Iniciando ação com parâmetros:\n{json.dumps(values, indent=2, ensure_ascii=False)}")
        self.dialog.destroy()

    def save_config(self, values):
        try:
            config_dir = Path(__file__).parent.parent / "config" / "saved_attacks"
            config_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            config_file = config_dir / f"attack_config_{timestamp}.json"
            with open(config_file, "w", encoding="utf-8") as f:
                json.dump(values, f, indent=4, ensure_ascii=False)
        except Exception as e:
            messagebox.showerror("Erro", f"Erro ao salvar configuração: {e}")

class EvilJWTGUI:
    def __init__(self, master):
        self.master = master
        master.title("EVIL_JWT_FORCE")
        master.configure(bg="#1e1e1e")
        master.state('zoomed')

        # Definir o ícone da janela
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        icon_path = os.path.join(assets_dir, "icon.ico")
        if os.path.exists(icon_path):
            master.iconbitmap(icon_path)

        # Carregar imagens do layout
        logo1_path = os.path.join(assets_dir, "logo1.png")
        logo2_path = os.path.join(assets_dir, "logo2.png")
        logo3_path = os.path.join(assets_dir, "logo3.png")

        self.logo1_img = ImageTk.PhotoImage(Image.open(logo1_path).resize((480, 60), Image.LANCZOS))
        self.logo2_img = ImageTk.PhotoImage(Image.open(logo2_path).resize((480, 60), Image.LANCZOS))
        self.logo3_img = ImageTk.PhotoImage(Image.open(logo3_path).resize((480, 40), Image.LANCZOS))

        # Frame principal
        self.main_frame = tk.Frame(master, bg="#1e1e1e")
        self.main_frame.pack(expand=True, fill='both')

        # Logo de cima (descida maior)
        self.logo1_label = tk.Label(self.main_frame, image=self.logo1_img, bg="#1e1e1e")
        self.logo1_label.pack(pady=(80, 30))  # Desce mais a logo de cima

        # Frame para centralizar os botões
        self.button_frame = tk.Frame(self.main_frame, bg="#1e1e1e")
        self.button_frame.pack(pady=(0, 0))
        self.auto_button = tk.Button(self.button_frame, text="Modo Automático",
                                   command=self.run_auto_mode, width=22, height=2,
                                   bg="#444444", fg="#232323", font=("Arial", 16, "bold"),
                                   activebackground="#444444", activeforeground="#232323", relief="flat")
        self.auto_button.pack(pady=10, anchor='center')
        self.manual_button = tk.Button(self.button_frame, text="Modo Manual",
                                     command=self.show_manual_menu, width=22, height=2,
                                     bg="#444444", fg="#232323", font=("Arial", 16, "bold"),
                                     activebackground="#444444", activeforeground="#232323", relief="flat")
        self.manual_button.pack(pady=10, anchor='center')
        self.quit_button = tk.Button(self.button_frame, text="Sair",
                                   command=master.quit, width=22, height=2,
                                   bg="#b00a0a", fg="white", font=("Arial", 16, "bold"),
                                   activebackground="#b00a0a", activeforeground="white", relief="flat")
        self.quit_button.pack(pady=10, anchor='center')

        # Logos de baixo (mais espaçadas e mais para baixo)
        self.logo2_label = tk.Label(self.main_frame, image=self.logo2_img, bg="#1e1e1e")
        self.logo2_label.pack(pady=(100, 30))  # Mais para baixo e mais espaçamento
        self.logo3_label = tk.Label(self.main_frame, image=self.logo3_img, bg="#1e1e1e")
        self.logo3_label.pack(pady=(0, 60))    # Mais para baixo

        # Menu manual frame
        self.manual_frame = tk.Frame(master, bg="#1e1e1e")

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
                "Tipo de Payload": [
                    "Detecção Básica",
                    "Bypass de Autenticação",
                    "Manipulação de Saldo",
                    "Extração de Dados",
                    "Injeção Cega",
                    "Bypass WAF",
                    "Stacked Queries",
                    "Extração de Arquivos",
                    "Escrita em Arquivo",
                    "Bypass de Filtros"
                ],
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
        # Limpa widgets antigos se necessário
        for widget in self.manual_frame.winfo_children():
            widget.destroy()
        self.manual_title = tk.Label(self.manual_frame, 
                                   text="Menu de Comandos",
                                   fg="#b00a0a", bg="#1e1e1e",
                                   font=("Arial", 26, "bold"))
        self.manual_title.pack(pady=10, anchor='center')

        self.modules = {
            "Autenticação": "auth.py",
            "Gerar Wordlist": "wordlist_generator.py",
            "Brute Force": "bruteforce.py",
            "Descriptografar": "aes_decrypt.py",
            "SQL Injection": "sql_injector.py",
            "Simular Sentry": "sentry_simulator.py",
            "Gerar Relatórios": "report.py"
        }

        # Frame para centralizar os botões
        self.buttons_frame = tk.Frame(self.manual_frame, bg="#1e1e1e")
        self.buttons_frame.pack(expand=True, anchor='center')

        for module_name, module_file in self.modules.items():
            btn = tk.Button(self.buttons_frame,
                          text=module_name,
                          command=lambda mn=module_name, mf=module_file: self.run_module_with_title(mn, mf),
                          width=22, height=2,
                          bg="#b00a0a",
                          fg="white",
                          font=("Arial", 16, "bold"),
                          activebackground="#b00a0a", activeforeground="white", relief="flat")
            btn.pack(pady=10, anchor='center')

        # Botão voltar ao menu principal (agora aparece logo abaixo dos botões)
        self.back_button = tk.Button(self.manual_frame,
                                   text="Voltar ao Menu Principal",
                                   command=self.show_main_menu,
                                   width=22, height=2,
                                   bg="#b00a0a",
                                   fg="white",
                                   font=("Arial", 16, "bold"),
                                   activebackground="#b00a0a", activeforeground="white", relief="flat")
        self.back_button.pack(pady=20, anchor='center')

        # Adiciona logo1 abaixo dos botões do menu manual
        self.logo1_label_manual = tk.Label(self.manual_frame, image=self.logo1_img, bg="#1e1e1e")
        self.logo1_label_manual.pack(pady=(30, 10), anchor='center')

        self.back_button = tk.Button(self.manual_frame,
                                   text="Voltar ao Menu Principal",
                                   command=self.show_main_menu,
                                   width=22, height=2,
                                   bg="#666",
                                   fg="white",
                                   font=("Arial", 16, "bold"))
        self.back_button.pack(pady=20, anchor='center')

    def show_manual_menu(self):
        self.main_frame.pack_forget()
        self.manual_frame.pack(expand=True, fill='both')

    def show_main_menu(self):
        self.manual_frame.pack_forget()
        self.main_frame.pack(expand=True, fill='both')

    def run_auto_mode(self):
        AutoDialog(self.master)

    def run_module_with_title(self, module_name, module_file):
        # Passa o nome do módulo com a enumeração para o diálogo
        if module_file in self.module_fields:
            ModuleDialog(self.master, module_file, self.module_fields[module_file], custom_title=module_name)
        else:
            messagebox.showerror("Erro", f"Configuração não encontrada para o módulo: {module_file}")

class AutoDialog:
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        # Definir o ícone do dialog
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        icon_path = os.path.join(assets_dir, "icon.ico")
        if os.path.exists(icon_path):
            self.dialog.iconbitmap(icon_path)
        self.dialog.title("Modo Automático")
        self.dialog.geometry("600x400")  # Define tamanho fixo, NÃO maximiza
        self.dialog.configure(bg="#1e1e1e")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        # Logo no topo do dialog
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        icon_path = os.path.join(assets_dir, "icon.ico")
        if os.path.exists(icon_path):
            self.dialog.iconbitmap(icon_path)
        logo1_path = os.path.join(assets_dir, "logo1.png")
        self.logo1_img = ImageTk.PhotoImage(Image.open(logo1_path).resize((480, 60), Image.LANCZOS))
        logo1_label = tk.Label(self.dialog, image=self.logo1_img, bg="#1e1e1e")
        logo1_label.pack(pady=(20, 10))

        # Frame principal centralizado
        self.main_frame = tk.Frame(self.dialog, bg="#1e1e1e")
        self.main_frame.pack(expand=True, fill='both', padx=20, pady=20)

        # Campos centralizados e alinhados à esquerda
        tk.Label(
            self.main_frame, 
            text="URL do Alvo:", 
            bg="#1e1e1e", 
            fg="white",
            font=("Arial", 12, "bold"),
            anchor="w",
            width=22
        ).grid(row=0, column=0, pady=5, sticky='e')
        self.url_entry = tk.Entry(
            self.main_frame,
            bg="#2e2e2e",
            fg="white",
            width=40,
            font=("Arial", 12),
            justify="left"
        )
        self.url_entry.grid(row=0, column=1, pady=5, padx=10, sticky='w')

        # Área de saída (tk.Text) para mostrar logs/resultados em tempo real
        self.output_text = tk.Text(self.main_frame, bg="#181818", fg="#00FF00", font=("Consolas", 11), height=8, width=60)
        self.output_text.grid(row=2, column=0, columnspan=2, pady=(10, 0), sticky='nsew')
        self.main_frame.grid_rowconfigure(2, weight=1)
        self.main_frame.grid_columnconfigure(1, weight=1)

        # Botão de ação centralizado abaixo dos campos
        self.action_frame = tk.Frame(self.main_frame, bg="#1e1e1e")
        self.action_frame.grid(row=1, column=0, columnspan=2, pady=(20,0))
        self.start_button = tk.Button(
            self.action_frame,
            text="Iniciar Ataque",
            command=self.start_auto_attack,
            bg="#b00a0a",
            fg="white",
            font=("Arial", 24, "bold"),
            height=1,  # Diminui a altura
            activebackground="#b00a0a", activeforeground="white", relief="flat"
        )
        self.start_button.pack(anchor='center', pady=(0, 18), ipadx=40)  # Diminui largura e aumenta espaçamento inferior

        self.close_button = tk.Button(
            self.action_frame,
            text="Fechar",
            command=self.dialog.destroy,
            bg="#444444",
            fg="white",
            font=("Arial", 14, "bold"),
            width=12,
            activebackground="#444444", activeforeground="white", relief="flat"
        )
        self.close_button.pack(anchor='center', pady=(0, 0))

        # Espaçador invisível para garantir 200px até o final da janela
        self.spacer = tk.Frame(self.dialog, height=200, bg="#1e1e1e")
        self.spacer.pack(side='bottom')

    def start_auto_attack(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Erro", "Por favor, insira uma URL válida")
            return
        self.save_url(url)
        # Executa o backend real e mostra o resultado em tempo real no tk.Text
        try:
            script_path = os.path.join(os.path.dirname(__file__), "..", "modules", "auto_scanner.py")
            script_path = os.path.abspath(script_path)
            # Executa o script Python passando a URL como argumento
            process = subprocess.Popen(
                ["python", script_path, "--url", url],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            self.output_text.delete(1.0, tk.END)
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break
                self.output_text.insert(tk.END, line)
                self.output_text.see(tk.END)
                self.output_text.update()
            process.stdout.close()
            process.wait()
            if process.returncode == 0:
                self.output_text.insert(tk.END, "\n[✔] Ataque automático finalizado com sucesso.\n")
            else:
                self.output_text.insert(tk.END, f"\n[✖] Erro na execução do backend (código {process.returncode}).\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"\n[✖] Falha ao executar o backend: {e}\n")
        # Não fecha o diálogo automaticamente, deixa o usuário analisar a saída

if __name__ == "__main__":
    root = tk.Tk()
    # Janela maximizada ao iniciar
    assets_dir = os.path.join(os.path.dirname(__file__), "assets")
    icon_path = os.path.join(assets_dir, "icon.ico")
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)
    root.state('zoomed')
    app = EvilJWTGUI(root)
    root.mainloop()

class EvilJWTGUI:
    def setup_manual_menu(self):
        # Limpa widgets antigos se necessário
        for widget in self.manual_frame.winfo_children():
            widget.destroy()
        self.manual_title = tk.Label(self.manual_frame, 
                                   text="Menu de Comandos",
                                   fg="#b00a0a", bg="#1e1e1e",
                                   font=("Arial", 26, "bold"))
        self.manual_title.pack(pady=10, anchor='center')

        self.modules = {
            "Autenticação": "auth.py",
            "Gerar Wordlist": "wordlist_generator.py",
            "Brute Force": "bruteforce.py",
            "Descriptografar": "aes_decrypt.py",
            "SQL Injection": "sql_injector.py",
            "Simular Sentry": "sentry_simulator.py",
            "Gerar Relatórios": "report.py"
        }

        # Frame para centralizar os botões
        self.buttons_frame = tk.Frame(self.manual_frame, bg="#1e1e1e")
        self.buttons_frame.pack(expand=True, anchor='center')

        for module_name, module_file in self.modules.items():
            btn = tk.Button(self.buttons_frame,
                          text=module_name,
                          command=lambda mn=module_name, mf=module_file: self.run_module_with_title(mn, mf),
                          width=22, height=2,
                          bg="#b00a0a",
                          fg="white",
                          font=("Arial", 16, "bold"),
                          activebackground="#b00a0a", activeforeground="white", relief="flat")
            btn.pack(pady=10, anchor='center')

        # Botão voltar ao menu principal (agora aparece logo abaixo dos botões)
        self.back_button = tk.Button(self.manual_frame,
                                   text="Voltar ao Menu Principal",
                                   command=self.show_main_menu,
                                   width=22, height=2,
                                   bg="#b00a0a",
                                   fg="white",
                                   font=("Arial", 16, "bold"),
                                   activebackground="#b00a0a", activeforeground="white", relief="flat")
        self.back_button.pack(pady=20, anchor='center')

        # Adiciona logo1 abaixo dos botões do menu manual
        self.logo1_label_manual = tk.Label(self.manual_frame, image=self.logo1_img, bg="#1e1e1e")
        self.logo1_label_manual.pack(pady=(30, 10), anchor='center')

        self.back_button = tk.Button(self.manual_frame,
                                   text="Voltar ao Menu Principal",
                                   command=self.show_main_menu,
                                   width=22, height=2,
                                   bg="#666",
                                   fg="white",
                                   font=("Arial", 16, "bold"))
        self.back_button.pack(pady=20, anchor='center')

    def show_manual_menu(self):
        self.main_frame.pack_forget()
        self.manual_frame.pack(expand=True, fill='both')

    def show_main_menu(self):
        self.manual_frame.pack_forget()
        self.main_frame.pack(expand=True, fill='both')

    def run_auto_mode(self):
        AutoDialog(self.master)

    def run_module_with_title(self, module_name, module_file):
        # Passa o nome do módulo com a enumeração para o diálogo
        if module_file in self.module_fields:
            ModuleDialog(self.master, module_file, self.module_fields[module_file], custom_title=module_name)
        else:
            messagebox.showerror("Erro", f"Configuração não encontrada para o módulo: {module_file}")

class AutoDialog:
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        # Definir o ícone do dialog
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        icon_path = os.path.join(assets_dir, "icon.ico")
        if os.path.exists(icon_path):
            self.dialog.iconbitmap(icon_path)
        self.dialog.title("Modo Automático")
        self.dialog.geometry("500x300")
        self.dialog.configure(bg="#1e1e1e")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        # Logo no topo do dialog
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        logo1_path = os.path.join(assets_dir, "logo1.png")
        self.logo1_img = ImageTk.PhotoImage(Image.open(logo1_path).resize((480, 60), Image.LANCZOS))
        logo1_label = tk.Label(self.dialog, image=self.logo1_img, bg="#1e1e1e")
        logo1_label.pack(pady=(20, 10))

        # Frame principal centralizado
        self.main_frame = tk.Frame(self.dialog, bg="#1e1e1e")
        self.main_frame.pack(expand=True, fill='both', padx=20, pady=20)

        # Campos centralizados e alinhados à esquerda
        tk.Label(
            self.main_frame, 
            text="URL do Alvo:", 
            bg="#1e1e1e", 
            fg="white",
            font=("Arial", 12, "bold"),
            anchor="w",
            width=22
        ).grid(row=0, column=0, pady=5, sticky='e')
        self.url_entry = tk.Entry(
            self.main_frame,
            bg="#2e2e2e",
            fg="white",
            width=40,
            font=("Arial", 12),
            justify="left"
        )
        self.url_entry.grid(row=0, column=1, pady=5, padx=10, sticky='w')

        # Botão de ação centralizado abaixo dos campos
        self.action_frame = tk.Frame(self.main_frame, bg="#1e1e1e")
        self.action_frame.grid(row=1, column=0, columnspan=2, pady=(20,0))
        self.start_button = tk.Button(
            self.action_frame,
            text="Iniciar Ataque Automático",
            command=self.start_auto_attack,
            bg="#b00a0a",  # Vermelho escuro igual ao botão voltar
            fg="white",
            font=("Arial", 16, "bold"),
            width=22, height=2,
            activebackground="#b00a0a", activeforeground="white", relief="flat"
        )
        self.start_button.pack(anchor='center', pady=10)

    def start_auto_attack(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Erro", "Por favor, insira uma URL válida")
            return
        self.save_url(url)
        # Executa o backend real e mostra o resultado em tempo real no tk.Text
        try:
            script_path = os.path.join(os.path.dirname(__file__), "..", "modules", "auto_scanner.py")
            script_path = os.path.abspath(script_path)
            # Executa o script Python passando a URL como argumento
            process = subprocess.Popen(
                ["python", script_path, "--url", url],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            self.output_text.delete(1.0, tk.END)
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break
                self.output_text.insert(tk.END, line)
                self.output_text.see(tk.END)
                self.output_text.update()
            process.stdout.close()
            process.wait()
            if process.returncode == 0:
                self.output_text.insert(tk.END, "\n[✔] Ataque automático finalizado com sucesso.\n")
            else:
                self.output_text.insert(tk.END, f"\n[✖] Erro na execução do backend (código {process.returncode}).\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"\n[✖] Falha ao executar o backend: {e}\n")
        # Não fecha o diálogo automaticamente, deixa o usuário analisar a saída

if __name__ == "__main__":
    root = tk.Tk()
    # Janela maximizada ao iniciar
    assets_dir = os.path.join(os.path.dirname(__file__), "assets")
    icon_path = os.path.join(assets_dir, "icon.ico")
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)
    root.state('zoomed')
    app = EvilJWTGUI(root)
    root.mainloop()

class EvilJWTGUI:
    def setup_manual_menu(self):
        # Limpa widgets antigos se necessário
        for widget in self.manual_frame.winfo_children():
            widget.destroy()
        self.manual_title = tk.Label(self.manual_frame, 
                                   text="Menu de Comandos",
                                   fg="#b00a0a", bg="#1e1e1e",
                                   font=("Arial", 26, "bold"))
        self.manual_title.pack(pady=10, anchor='center')

        self.modules = {
            "Autenticação": "auth.py",
            "Gerar Wordlist": "wordlist_generator.py",
            "Brute Force": "bruteforce.py",
            "Descriptografar": "aes_decrypt.py",
            "SQL Injection": "sql_injector.py",
            "Simular Sentry": "sentry_simulator.py",
            "Gerar Relatórios": "report.py"
        }

        # Frame para centralizar os botões
        self.buttons_frame = tk.Frame(self.manual_frame, bg="#1e1e1e")
        self.buttons_frame.pack(expand=True, anchor='center')

        for module_name, module_file in self.modules.items():
            btn = tk.Button(self.buttons_frame,
                          text=module_name,
                          command=lambda mn=module_name, mf=module_file: self.run_module_with_title(mn, mf),
                          width=22, height=2,
                          bg="#b00a0a",
                          fg="white",
                          font=("Arial", 16, "bold"),
                          activebackground="#b00a0a", activeforeground="white", relief="flat")
            btn.pack(pady=10, anchor='center')

        # Botão voltar ao menu principal (agora aparece logo abaixo dos botões)
        self.back_button = tk.Button(self.manual_frame,
                                   text="Voltar ao Menu Principal",
                                   command=self.show_main_menu,
                                   width=22, height=2,
                                   bg="#b00a0a",
                                   fg="white",
                                   font=("Arial", 16, "bold"),
                                   activebackground="#b00a0a", activeforeground="white", relief="flat")
        self.back_button.pack(pady=20, anchor='center')

        # Adiciona logo1 abaixo dos botões do menu manual
        self.logo1_label_manual = tk.Label(self.manual_frame, image=self.logo1_img, bg="#1e1e1e")
        self.logo1_label_manual.pack(pady=(30, 10), anchor='center')

        self.back_button = tk.Button(self.manual_frame,
                                   text="Voltar ao Menu Principal",
                                   command=self.show_main_menu,
                                   width=22, height=2,
                                   bg="#666",
                                   fg="white",
                                   font=("Arial", 16, "bold"))
        self.back_button.pack(pady=20, anchor='center')

    def show_manual_menu(self):
        self.main_frame.pack_forget()
        self.manual_frame.pack(expand=True, fill='both')

    def show_main_menu(self):
        self.manual_frame.pack_forget()
        self.main_frame.pack(expand=True, fill='both')

    def run_auto_mode(self):
        AutoDialog(self.master)

    def run_module_with_title(self, module_name, module_file):
        # Passa o nome do módulo com a enumeração para o diálogo
        if module_file in self.module_fields:
            ModuleDialog(self.master, module_file, self.module_fields[module_file], custom_title=module_name)
        else:
            messagebox.showerror("Erro", f"Configuração não encontrada para o módulo: {module_file}")

class AutoDialog:
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        # Definir o ícone do dialog
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        icon_path = os.path.join(assets_dir, "icon.ico")
        if os.path.exists(icon_path):
            self.dialog.iconbitmap(icon_path)
        self.dialog.title("Modo Automático")
        self.dialog.geometry("500x300")
        self.dialog.configure(bg="#1e1e1e")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        # Logo no topo do dialog
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        logo1_path = os.path.join(assets_dir, "logo1.png")
        self.logo1_img = ImageTk.PhotoImage(Image.open(logo1_path).resize((480, 60), Image.LANCZOS))
        logo1_label = tk.Label(self.dialog, image=self.logo1_img, bg="#1e1e1e")
        logo1_label.pack(pady=(20, 10))

        # Frame principal centralizado
        self.main_frame = tk.Frame(self.dialog, bg="#1e1e1e")
        self.main_frame.pack(expand=True, fill='both', padx=20, pady=20)

        # Campos centralizados e alinhados à esquerda
        tk.Label(
            self.main_frame, 
            text="URL do Alvo:", 
            bg="#1e1e1e", 
            fg="white",
            font=("Arial", 12, "bold"),
            anchor="w",
            width=22
        ).grid(row=0, column=0, pady=5, sticky='e')
        self.url_entry = tk.Entry(
            self.main_frame,
            bg="#2e2e2e",
            fg="white",
            width=40,
            font=("Arial", 12),
            justify="left"
        )
        self.url_entry.grid(row=0, column=1, pady=5, padx=10, sticky='w')

        # Botão de ação centralizado abaixo dos campos
        self.action_frame = tk.Frame(self.main_frame, bg="#1e1e1e")
        self.action_frame.grid(row=1, column=0, columnspan=2, pady=(20,0))
        self.start_button = tk.Button(
            self.action_frame,
            text="Iniciar Ataque Automático",
            command=self.start_auto_attack,
            bg="#b00a0a",  # Vermelho escuro igual ao botão voltar
            fg="white",
            font=("Arial", 16, "bold"),
            width=22, height=2,
            activebackground="#b00a0a", activeforeground="white", relief="flat"
        )
        self.start_button.pack(anchor='center', pady=10)

    def start_auto_attack(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Erro", "Por favor, insira uma URL válida")
            return
        self.save_url(url)
        # Executa o backend real e mostra o resultado em tempo real no tk.Text
        try:
            script_path = os.path.join(os.path.dirname(__file__), "..", "modules", "auto_scanner.py")
            script_path = os.path.abspath(script_path)
            # Executa o script Python passando a URL como argumento
            process = subprocess.Popen(
                ["python", script_path, "--url", url],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            self.output_text.delete(1.0, tk.END)
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break
                self.output_text.insert(tk.END, line)
                self.output_text.see(tk.END)
                self.output_text.update()
            process.stdout.close()
            process.wait()
            if process.returncode == 0:
                self.output_text.insert(tk.END, "\n[✔] Ataque automático finalizado com sucesso.\n")
            else:
                self.output_text.insert(tk.END, f"\n[✖] Erro na execução do backend (código {process.returncode}).\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"\n[✖] Falha ao executar o backend: {e}\n")
        # Não fecha o diálogo automaticamente, deixa o usuário analisar a saída

if __name__ == "__main__":
    root = tk.Tk()
    # Janela maximizada ao iniciar
    assets_dir = os.path.join(os.path.dirname(__file__), "assets")
    icon_path = os.path.join(assets_dir, "icon.ico")
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)
    root.state('zoomed')
    app = EvilJWTGUI(root)
    root.mainloop()

class EvilJWTGUI:
    def setup_manual_menu(self):
        # Limpa widgets antigos se necessário
        for widget in self.manual_frame.winfo_children():
            widget.destroy()
        self.manual_title = tk.Label(self.manual_frame, 
                                   text="Menu de Comandos",
                                   fg="#b00a0a", bg="#1e1e1e",
                                   font=("Arial", 26, "bold"))
        self.manual_title.pack(pady=10, anchor='center')

        self.modules = {
            "Autenticação": "auth.py",
            "Gerar Wordlist": "wordlist_generator.py",
            "Brute Force": "bruteforce.py",
            "Descriptografar": "aes_decrypt.py",
            "SQL Injection": "sql_injector.py",
            "Simular Sentry": "sentry_simulator.py",
            "Gerar Relatórios": "report.py"
        }

        # Frame para centralizar os botões
        self.buttons_frame = tk.Frame(self.manual_frame, bg="#1e1e1e")
        self.buttons_frame.pack(expand=True, anchor='center')

        for module_name, module_file in self.modules.items():
            btn = tk.Button(self.buttons_frame,
                          text=module_name,
                          command=lambda mn=module_name, mf=module_file: self.run_module_with_title(mn, mf),
                          width=22, height=2,
                          bg="#b00a0a",
                          fg="white",
                          font=("Arial", 16, "bold"),
                          activebackground="#b00a0a", activeforeground="white", relief="flat")
            btn.pack(pady=10, anchor='center')

        # Botão voltar ao menu principal (agora aparece logo abaixo dos botões)
        self.back_button = tk.Button(self.manual_frame,
                                   text="Voltar ao Menu Principal",
                                   command=self.show_main_menu,
                                   width=22, height=2,
                                   bg="#b00a0a",
                                   fg="white",
                                   font=("Arial", 16, "bold"),
                                   activebackground="#b00a0a", activeforeground="white", relief="flat")
        self.back_button.pack(pady=20, anchor='center')

        # Adiciona logo1 abaixo dos botões do menu manual
        self.logo1_label_manual = tk.Label(self.manual_frame, image=self.logo1_img, bg="#1e1e1e")
        self.logo1_label_manual.pack(pady=(30, 10), anchor='center')

        self.back_button = tk.Button(self.manual_frame,
                                   text="Voltar ao Menu Principal",
                                   command=self.show_main_menu,
                                   width=22, height=2,
                                   bg="#666",
                                   fg="white",
                                   font=("Arial", 16, "bold"))
        self.back_button.pack(pady=20, anchor='center')

    def show_manual_menu(self):
        self.main_frame.pack_forget()
        self.manual_frame.pack(expand=True, fill='both')

    def show_main_menu(self):
        self.manual_frame.pack_forget()
        self.main_frame.pack(expand=True, fill='both')

    def run_auto_mode(self):
        AutoDialog(self.master)

    def run_module_with_title(self, module_name, module_file):
        # Passa o nome do módulo com a enumeração para o diálogo
        if module_file in self.module_fields:
            ModuleDialog(self.master, module_file, self.module_fields[module_file], custom_title=module_name)
        else:
            messagebox.showerror("Erro", f"Configuração não encontrada para o módulo: {module_file}")

class AutoDialog:
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        # Definir o ícone do dialog
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        icon_path = os.path.join(assets_dir, "icon.ico")
        if os.path.exists(icon_path):
            self.dialog.iconbitmap(icon_path)
        self.dialog.title("Modo Automático")
        self.dialog.geometry("500x300")
        self.dialog.configure(bg="#1e1e1e")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        # Logo no topo do dialog
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        logo1_path = os.path.join(assets_dir, "logo1.png")
        self.logo1_img = ImageTk.PhotoImage(Image.open(logo1_path).resize((480, 60), Image.LANCZOS))
        logo1_label = tk.Label(self.dialog, image=self.logo1_img, bg="#1e1e1e")
        logo1_label.pack(pady=(20, 10))

        # Frame principal centralizado
        self.main_frame = tk.Frame(self.dialog, bg="#1e1e1e")
        self.main_frame.pack(expand=True, fill='both', padx=20, pady=20)

        # Campos centralizados e alinhados à esquerda
        tk.Label(
            self.main_frame, 
            text="URL do Alvo:", 
            bg="#1e1e1e", 
            fg="white",
            font=("Arial", 12, "bold"),
            anchor="w",
            width=22
        ).grid(row=0, column=0, pady=5, sticky='e')
        self.url_entry = tk.Entry(
            self.main_frame,
            bg="#2e2e2e",
            fg="white",
            width=40,
            font=("Arial", 12),
            justify="left"
        )
        self.url_entry.grid(row=0, column=1, pady=5, padx=10, sticky='w')

        # Botão de ação centralizado abaixo dos campos
        self.action_frame = tk.Frame(self.main_frame, bg="#1e1e1e")
        self.action_frame.grid(row=1, column=0, columnspan=2, pady=(20,0))
        self.start_button = tk.Button(
            self.action_frame,
            text="Iniciar Ataque Automático",
            command=self.start_auto_attack,
            bg="#b00a0a",  # Vermelho escuro igual ao botão voltar
            fg="white",
            font=("Arial", 16, "bold"),
            width=22, height=2,
            activebackground="#b00a0a", activeforeground="white", relief="flat"
        )
        self.start_button.pack(anchor='center', pady=10)

    def start_auto_attack(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Erro", "Por favor, insira uma URL válida")
            return
        self.save_url(url)
        # Executa o backend real e mostra o resultado em tempo real no tk.Text
        try:
            script_path = os.path.join(os.path.dirname(__file__), "..", "modules", "auto_scanner.py")
            script_path = os.path.abspath(script_path)
            # Executa o script Python passando a URL como argumento
            process = subprocess.Popen(
                ["python", script_path, "--url", url],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            self.output_text.delete(1.0, tk.END)
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break
                self.output_text.insert(tk.END, line)
                self.output_text.see(tk.END)
                self.output_text.update()
            process.stdout.close()
            process.wait()
            if process.returncode == 0:
                self.output_text.insert(tk.END, "\n[✔] Ataque automático finalizado com sucesso.\n")
            else:
                self.output_text.insert(tk.END, f"\n[✖] Erro na execução do backend (código {process.returncode}).\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"\n[✖] Falha ao executar o backend: {e}\n")
        # Não fecha o diálogo automaticamente, deixa o usuário analisar a saída

if __name__ == "__main__":
    root = tk.Tk()
    # Janela maximizada ao iniciar
    assets_dir = os.path.join(os.path.dirname(__file__), "assets")
    icon_path = os.path.join(assets_dir, "icon.ico")
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)
    root.state('zoomed')
    app = EvilJWTGUI(root)
    root.mainloop()

class EvilJWTGUI:
    def setup_manual_menu(self):
        # Limpa widgets antigos se necessário
        for widget in self.manual_frame.winfo_children():
            widget.destroy()
        self.manual_title = tk.Label(self.manual_frame, 
                                   text="Menu de Comandos",
                                   fg="#b00a0a", bg="#1e1e1e",
                                   font=("Arial", 26, "bold"))
        self.manual_title.pack(pady=10, anchor='center')

        self.modules = {
            "Autenticação": "auth.py",
            "Gerar Wordlist": "wordlist_generator.py",
            "Brute Force": "bruteforce.py",
            "Descriptografar": "aes_decrypt.py",
            "SQL Injection": "sql_injector.py",
            "Simular Sentry": "sentry_simulator.py",
            "Gerar Relatórios": "report.py"
        }

        # Frame para centralizar os botões
        self.buttons_frame = tk.Frame(self.manual_frame, bg="#1e1e1e")
        self.buttons_frame.pack(expand=True, anchor='center')

        for module_name, module_file in self.modules.items():
            btn = tk.Button(self.buttons_frame,
                          text=module_name,
                          command=lambda mn=module_name, mf=module_file: self.run_module_with_title(mn, mf),
                          width=22, height=2,
                          bg="#b00a0a",
                          fg="white",
                          font=("Arial", 16, "bold"),
                          activebackground="#b00a0a", activeforeground="white", relief="flat")
            btn.pack(pady=10, anchor='center')

        # Botão voltar ao menu principal (agora aparece logo abaixo dos botões)
        self.back_button = tk.Button(self.manual_frame,
                                   text="Voltar ao Menu Principal",
                                   command=self.show_main_menu,
                                   width=22, height=2,
                                   bg="#b00a0a",
                                   fg="white",
                                   font=("Arial", 16, "bold"),
                                   activebackground="#b00a0a", activeforeground="white", relief="flat")
        self.back_button.pack(pady=20, anchor='center')

        # Adiciona logo1 abaixo dos botões do menu manual
        self.logo1_label_manual = tk.Label(self.manual_frame, image=self.logo1_img, bg="#1e1e1e")
        self.logo1_label_manual.pack(pady=(30, 10), anchor='center')

        self.back_button = tk.Button(self.manual_frame,
                                   text="Voltar ao Menu Principal",
                                   command=self.show_main_menu,
                                   width=22, height=2,
                                   bg="#666",
                                   fg="white",
                                   font=("Arial", 16, "bold"))
        self.back_button.pack(pady=20, anchor='center')

    def show_manual_menu(self):
        self.main_frame.pack_forget()
        self.manual_frame.pack(expand=True, fill='both')

    def show_main_menu(self):
        self.manual_frame.pack_forget()
        self.main_frame.pack(expand=True, fill='both')

    def run_auto_mode(self):
        AutoDialog(self.master)

    def run_module_with_title(self, module_name, module_file):
        # Passa o nome do módulo com a enumeração para o diálogo
        if module_file in self.module_fields:
            ModuleDialog(self.master, module_file, self.module_fields[module_file], custom_title=module_name)
        else:
            messagebox.showerror("Erro", f"Configuração não encontrada para o módulo: {module_file}")

class AutoDialog:
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        # Definir o ícone do dialog
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        icon_path = os.path.join(assets_dir, "icon.ico")
        if os.path.exists(icon_path):
            self.dialog.iconbitmap(icon_path)
        self.dialog.title("Modo Automático")
        self.dialog.geometry("500x300")
        self.dialog.configure(bg="#1e1e1e")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        # Logo no topo do dialog
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        logo1_path = os.path.join(assets_dir, "logo1.png")
        self.logo1_img = ImageTk.PhotoImage(Image.open(logo1_path).resize((480, 60), Image.LANCZOS))
        logo1_label = tk.Label(self.dialog, image=self.logo1_img, bg="#1e1e1e")
        logo1_label.pack(pady=(20, 10))

        # Frame principal centralizado
        self.main_frame = tk.Frame(self.dialog, bg="#1e1e1e")
        self.main_frame.pack(expand=True, fill='both', padx=20, pady=20)

        # Campos centralizados e alinhados à esquerda
        tk.Label(
            self.main_frame, 
            text="URL do Alvo:", 
            bg="#1e1e1e", 
            fg="white",
            font=("Arial", 12, "bold"),
            anchor="w",
            width=22
        ).grid(row=0, column=0, pady=5, sticky='e')
        self.url_entry = tk.Entry(
            self.main_frame,
            bg="#2e2e2e",
            fg="white",
            width=40,
            font=("Arial", 12),
            justify="left"
        )
        self.url_entry.grid(row=0, column=1, pady=5, padx=10, sticky='w')

        # Botão de ação centralizado abaixo dos campos
        self.action_frame = tk.Frame(self.main_frame, bg="#1e1e1e")
        self.action_frame.grid(row=1, column=0, columnspan=2, pady=(20,0))
        self.start_button = tk.Button(
            self.action_frame,
            text="Iniciar Ataque Automático",
            command=self.start_auto_attack,
            bg="#b00a0a",  # Vermelho escuro igual ao botão voltar
            fg="white",
            font=("Arial", 16, "bold"),
            width=22, height=2,
            activebackground="#b00a0a", activeforeground="white", relief="flat"
        )
        self.start_button.pack(anchor='center', pady=10)

    def start_auto_attack(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Erro", "Por favor, insira uma URL válida")
            return
        self.save_url(url)
        # Executa o backend real e mostra o resultado em tempo real no tk.Text
        try:
            script_path = os.path.join(os.path.dirname(__file__), "..", "modules", "auto_scanner.py")
            script_path = os.path.abspath(script_path)
            # Executa o script Python passando a URL como argumento
            process = subprocess.Popen(
                ["python", script_path, "--url", url],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            self.output_text.delete(1.0, tk.END)
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break
                self.output_text.insert(tk.END, line)
                self.output_text.see(tk.END)
                self.output_text.update()
            process.stdout.close()
            process.wait()
            if process.returncode == 0:
                self.output_text.insert(tk.END, "\n[✔] Ataque automático finalizado com sucesso.\n")
            else:
                self.output_text.insert(tk.END, f"\n[✖] Erro na execução do backend (código {process.returncode}).\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"\n[✖] Falha ao executar o backend: {e}\n")
        # Não fecha o diálogo automaticamente, deixa o usuário analisar a saída

if __name__ == "__main__":
    root = tk.Tk()
    # Janela maximizada ao iniciar
    assets_dir = os.path.join(os.path.dirname(__file__), "assets")
    icon_path = os.path.join(assets_dir, "icon.ico")
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)
    root.state('zoomed')
    app = EvilJWTGUI(root)
    root.mainloop()

class EvilJWTGUI:
    def setup_manual_menu(self):
        # Limpa widgets antigos se necessário
        for widget in self.manual_frame.winfo_children():
            widget.destroy()
        self.manual_title = tk.Label(self.manual_frame, 
                                   text="Menu de Comandos",
                                   fg="#b00a0a", bg="#1e1e1e",
                                   font=("Arial", 26, "bold"))
        self.manual_title.pack(pady=10, anchor='center')

        self.modules = {
            "Autenticação": "auth.py",
            "Gerar Wordlist": "wordlist_generator.py",
            "Brute Force": "bruteforce.py",
            "Descriptografar": "aes_decrypt.py",
            "SQL Injection": "sql_injector.py",
            "Simular Sentry": "sentry_simulator.py",
            "Gerar Relatórios": "report.py"
        }

        # Frame para centralizar os botões
        self.buttons_frame = tk.Frame(self.manual_frame, bg="#1e1e1e")
        self.buttons_frame.pack(expand=True, anchor='center')

        for module_name, module_file in self.modules.items():
            btn = tk.Button(self.buttons_frame,
                          text=module_name,
                          command=lambda mn=module_name, mf=module_file: self.run_module_with_title(mn, mf),
                          width=22, height=2,
                          bg="#b00a0a",
                          fg="white",
                          font=("Arial", 16, "bold"),
                          activebackground="#b00a0a", activeforeground="white", relief="flat")
            btn.pack(pady=10, anchor='center')

        # Botão voltar ao menu principal (agora aparece logo abaixo dos botões)
        self.back_button = tk.Button(self.manual_frame,
                                   text="Voltar ao Menu Principal",
                                   command=self.show_main_menu,
                                   width=22, height=2,
                                   bg="#b00a0a",
                                   fg="white",
                                   font=("Arial", 16, "bold"),
                                   activebackground="#b00a0a", activeforeground="white", relief="flat")
        self.back_button.pack(pady=20, anchor='center')

        # Adiciona logo1 abaixo dos botões do menu manual
        self.logo1_label_manual = tk.Label(self.manual_frame, image=self.logo1_img, bg="#1e1e1e")
        self.logo1_label_manual.pack(pady=(30, 10), anchor='center')

        self.back_button = tk.Button(self.manual_frame,
                                   text="Voltar ao Menu Principal",
                                   command=self.show_main_menu,
                                   width=22, height=2,
                                   bg="#666",
                                   fg="white",
                                   font=("Arial", 16, "bold"))
        self.back_button.pack(pady=20, anchor='center')

    def show_manual_menu(self):
        self.main_frame.pack_forget()
        self.manual_frame.pack(expand=True, fill='both')

    def show_main_menu(self):
        self.manual_frame.pack_forget()
        self.main_frame.pack(expand=True, fill='both')

    def run_auto_mode(self):
        AutoDialog(self.master)

    def run_module_with_title(self, module_name, module_file):
        # Passa o nome do módulo com a enumeração para o diálogo
        if module_file in self.module_fields:
            ModuleDialog(self.master, module_file, self.module_fields[module_file], custom_title=module_name)
        else:
            messagebox.showerror("Erro", f"Configuração não encontrada para o módulo: {module_file}")

class AutoDialog:
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        # Definir o ícone do dialog
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        icon_path = os.path.join(assets_dir, "icon.ico")
        if os.path.exists(icon_path):
            self.dialog.iconbitmap(icon_path)
        self.dialog.title("Modo Automático")
        self.dialog.geometry("500x300")
        self.dialog.configure(bg="#1e1e1e")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        # Logo no topo do dialog
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        logo1_path = os.path.join(assets_dir, "logo1.png")
        self.logo1_img = ImageTk.PhotoImage(Image.open(logo1_path).resize((480, 60), Image.LANCZOS))
        logo1_label = tk.Label(self.dialog, image=self.logo1_img, bg="#1e1e1e")
        logo1_label.pack(pady=(20, 10))

        # Frame principal centralizado
        self.main_frame = tk.Frame(self.dialog, bg="#1e1e1e")
        self.main_frame.pack(expand=True, fill='both', padx=20, pady=20)

        # Campos centralizados e alinhados à esquerda
        tk.Label(
            self.main_frame, 
            text="URL do Alvo:", 
            bg="#1e1e1e", 
            fg="white",
            font=("Arial", 12, "bold"),
            anchor="w",
            width=22
        ).grid(row=0, column=0, pady=5, sticky='e')
        self.url_entry = tk.Entry(
            self.main_frame,
            bg="#2e2e2e",
            fg="white",
            width=40,
            font=("Arial", 12),
            justify="left"
        )
        self.url_entry.grid(row=0, column=1, pady=5, padx=10, sticky='w')

        # Botão de ação centralizado abaixo dos campos
        self.action_frame = tk.Frame(self.main_frame, bg="#1e1e1e")
        self.action_frame.grid(row=1, column=0, columnspan=2, pady=(20,0))
        self.start_button = tk.Button(
            self.action_frame,
            text="Iniciar Ataque Automático",
            command=self.start_auto_attack,
            bg="#b00a0a",  # Vermelho escuro igual ao botão voltar
            fg="white",
            font=("Arial", 16, "bold"),
            width=22, height=2,
            activebackground="#b00a0a", activeforeground="white", relief="flat"
        )
        self.start_button.pack(anchor='center', pady=10)

    def start_auto_attack(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Erro", "Por favor, insira uma URL válida")
            return
        self.save_url(url)
        # Executa o backend real e mostra o resultado em tempo real no tk.Text
        try:
            script_path = os.path.join(os.path.dirname(__file__), "..", "modules", "auto_scanner.py")
            script_path = os.path.abspath(script_path)
            # Executa o script Python passando a URL como argumento
            process = subprocess.Popen(
                ["python", script_path, "--url", url],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            self.output_text.delete(1.0, tk.END)
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break
                self.output_text.insert(tk.END, line)
                self.output_text.see(tk.END)
                self.output_text.update()
            process.stdout.close()
            process.wait()
            if process.returncode == 0:
                self.output_text.insert(tk.END, "\n[✔] Ataque automático finalizado com sucesso.\n")
            else:
                self.output_text.insert(tk.END, f"\n[✖] Erro na execução do backend (código {process.returncode}).\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"\n[✖] Falha ao executar o backend: {e}\n")
        # Não fecha o diálogo automaticamente, deixa o usuário analisar a saída

if __name__ == "__main__":
    root = tk.Tk()
    # Janela maximizada ao iniciar
    assets_dir = os.path.join(os.path.dirname(__file__), "assets")
    icon_path = os.path.join(assets_dir, "icon.ico")
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)
    root.state('zoomed')
    app = EvilJWTGUI(root)
    root.mainloop()

class EvilJWTGUI:
    def setup_manual_menu(self):
        # Limpa widgets antigos se necessário
        for widget in self.manual_frame.winfo_children():
            widget.destroy()
        self.manual_title = tk.Label(self.manual_frame, 
                                   text="Menu de Comandos",
                                   fg="#b00a0a", bg="#1e1e1e",
                                   font=("Arial", 26, "bold"))
        self.manual_title.pack(pady=10, anchor='center')

        self.modules = {
            "Autenticação": "auth.py",
            "Gerar Wordlist": "wordlist_generator.py",
            "Brute Force": "bruteforce.py",
            "Descriptografar": "aes_decrypt.py",
            "SQL Injection": "sql_injector.py",
            "Simular Sentry": "sentry_simulator.py",
            "Gerar Relatórios": "report.py"
        }

        # Frame para centralizar os botões
        self.buttons_frame = tk.Frame(self.manual_frame, bg="#1e1e1e")
        self.buttons_frame.pack(expand=True, anchor='center')

        for module_name, module_file in self.modules.items():
            btn = tk.Button(self.buttons_frame,
                          text=module_name,
                          command=lambda mn=module_name, mf=module_file: self.run_module_with_title(mn, mf),
                          width=22, height=2,
                          bg="#b00a0a",
                          fg="white",
                          font=("Arial", 16, "bold"),
                          activebackground="#b00a0a", activeforeground="white", relief="flat")
            btn.pack(pady=10, anchor='center')

        # Botão voltar ao menu principal (agora aparece logo abaixo dos botões)
        self.back_button = tk.Button(self.manual_frame,
                                   text="Voltar ao Menu Principal",
                                   command=self.show_main_menu,
                                   width=22, height=2,
                                   bg="#b00a0a",
                                   fg="white",
                                   font=("Arial", 16, "bold"),
                                   activebackground="#b00a0a", activeforeground="white", relief="flat")
        self.back_button.pack(pady=20, anchor='center')

        # Adiciona logo1 abaixo dos botões do menu manual
        self.logo1_label_manual = tk.Label(self.manual_frame, image=self.logo1_img, bg="#1e1e1e")
        self.logo1_label_manual.pack(pady=(30, 10), anchor='center')

        self.back_button = tk.Button(self.manual_frame,
                                   text="Voltar ao Menu Principal",
                                   command=self.show_main_menu,
                                   width=22, height=2,
                                   bg="#666",
                                   fg="white",
                                   font=("Arial", 16, "bold"))
        self.back_button.pack(pady=20, anchor='center')

    def show_manual_menu(self):
        self.main_frame.pack_forget()
        self.manual_frame.pack(expand=True, fill='both')

    def show_main_menu(self):
        self.manual_frame.pack_forget()
        self.main_frame.pack(expand=True, fill='both')

    def run_auto_mode(self):
        AutoDialog(self.master)

    def run_module_with_title(self, module_name, module_file):
        # Passa o nome do módulo com a enumeração para o diálogo
        if module_file in self.module_fields:
            ModuleDialog(self.master, module_file, self.module_fields[module_file], custom_title=module_name)
        else:
            messagebox.showerror("Erro", f"Configuração não encontrada para o módulo: {module_file}")

class AutoDialog:
    def __init__(self, parent):
        self.dialog = tk.Toplevel(parent)
        # Definir o ícone do dialog
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        icon_path = os.path.join(assets_dir, "icon.ico")
        if os.path.exists(icon_path):
            self.dialog.iconbitmap(icon_path)
        self.dialog.title("Modo Automático")
        self.dialog.geometry("500x300")
        self.dialog.configure(bg="#1e1e1e")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        # Logo no topo do dialog
        assets_dir = os.path.join(os.path.dirname(__file__), "assets")
        logo1_path = os.path.join(assets_dir, "logo1.png")
        self.logo1_img = ImageTk.PhotoImage(Image.open(logo1_path).resize((480, 60), Image.LANCZOS))
        logo1_label = tk.Label(self.dialog, image=self.logo1_img, bg="#1e1e1e")
        logo1_label.pack(pady=(20, 10))

        # Frame principal centralizado
        self.main_frame = tk.Frame(self.dialog, bg="#1e1e1e")
        self.main_frame.pack(expand=True, fill='both', padx=20, pady=20)

        # Campos centralizados e alinhados à esquerda
        tk.Label(
            self.main_frame, 
            text="URL do Alvo:", 
            bg="#1e1e1e", 
            fg="white",
            font=("Arial", 12, "bold"),
            anchor="w",
            width=22
        ).grid(row=0, column=0, pady=5, sticky='e')
        self.url_entry = tk.Entry(
            self.main_frame,
            bg="#2e2e2e",
            fg="white",
            width=40,
            font=("Arial", 12),
            justify="left"
        )
        self.url_entry.grid(row=0, column=1, pady=5, padx=10, sticky='w')

        # Botão de ação centralizado abaixo dos campos
        self.action_frame = tk.Frame(self.main_frame, bg="#1e1e1e")
        self.action_frame.grid(row=1, column=0, columnspan=2, pady=(20,0))
        self.start_button = tk.Button(
            self.action_frame,
            text="Iniciar Ataque Automático",
            command=self.start_auto_attack,
            bg="#b00a0a",  # Vermelho escuro igual ao botão voltar
            fg="white",
            font=("Arial", 16, "bold"),
            width=22, height=2,
            activebackground="#b00a0a", activeforeground="white", relief="flat"
        )
        self.start_button.pack(anchor='center', pady=10)

    def start_auto_attack(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showerror("Erro", "Por favor, insira uma URL válida")
            return
        self.save_url(url)
        # Executa o backend real e mostra o resultado em tempo real no tk.Text
        try:
            script_path = os.path.join(os.path.dirname(__file__), "..", "modules", "auto_scanner.py")
            script_path = os.path.abspath(script_path)
            # Executa o script Python passando a URL como argumento
            process = subprocess.Popen(
                ["python", script_path, "--url", url],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True
            )
            self.output_text.delete(1.0, tk.END)
            for line in iter(process.stdout.readline, ''):
                if not line:
                    break
                self.output_text.insert(tk.END, line)
                self.output_text.see(tk.END)
                self.output_text.update()
            process.stdout.close()
            process.wait()
            if process.returncode == 0:
                self.output_text.insert(tk.END, "\n[✔] Ataque automático finalizado com sucesso.\n")
            else:
                self.output_text.insert(tk.END, f"\n[✖] Erro na execução do backend (código {process.returncode}).\n")
        except Exception as e:
            self.output_text.insert(tk.END, f"\n[✖] Falha ao executar o backend: {e}\n")
        # Não fecha o diálogo automaticamente, deixa o usuário analisar a saída

if __name__ == "__main__":
    root = tk.Tk()
    # Janela maximizada ao iniciar
    assets_dir = os.path.join(os.path.dirname(__file__), "assets")
    icon_path = os.path.join(assets_dir, "icon.ico")
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)
    root.state('zoomed')
    app = EvilJWTGUI(root)
    root.mainloop()

class EvilJWTGUI:
    def setup_manual_menu(self):
        # Limpa widgets antigos se necessário
        for widget in self.manual_frame.winfo_children():
            widget.destroy()
        self.manual_title = tk.Label(self.manual_frame, 
                                   text="Menu de Comandos",
                                   fg="#b00a0a", bg="#1e1e1e",
                                   font=("Arial", 26, "bold"))
        self.manual_title.pack(pady=10, anchor='center')

        self.modules = {
            "Autenticação": "auth.py",
            "Gerar Wordlist": "wordlist_generator.py",
            "Brute Force": "bruteforce.py",
            "Descriptografar": "aes_decrypt.py",
            "SQL Injection": "sql_injector.py",
            "Simular Sentry": "sentry_simulator.py",
            "Gerar Relatórios": "report.py"
        }

        # Frame para centralizar os botões
        self.buttons_frame = tk.Frame(self.manual_frame, bg="#1e1e1e")
        self.buttons_frame.pack(expand=True, anchor='center')

        for module_name, module_file in self.modules.items():
            btn = tk.Button(self.buttons_frame,
                          text=module_name,
                          command=lambda mn=module_name, mf=module_file: self.run_module_with_title(mn, mf),
                          width=22, height=2,
                          bg="#b00a0a",
                          fg="white",
                          font=("Arial", 16, "bold"),
                          activebackground="#b00a0a", activeforeground="white", relief="flat")
            btn.pack(pady=10, anchor='center')

        # Botão voltar ao menu principal (agora aparece logo abaixo dos botões)
        self.back_button = tk.Button(self.manual_frame,
                                   text="Voltar ao Menu Principal",
                                   command=self.show_main_menu,
                                   width=22, height=2,
                                   bg="#b00a0a",
                                   fg="white",
                                   font=("Arial", 16, "bold"),
                                   activebackground="#b00a0a", activeforeground="white", relief="flat")
        self.back_button