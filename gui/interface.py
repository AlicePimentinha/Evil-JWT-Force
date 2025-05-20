# EVIL_JWT_FORCE/gui/interface.py
import tkinter as tk
from tkinter import ttk, messagebox
from typing import Dict, Any
import json
import sys
import os
import subprocess
from pathlib import Path

# Adiciona o diretório raiz ao PYTHONPATH
sys.path.append(str(Path(__file__).parent.parent))

from core.auth import Authenticator
from core.bruteforce import JWTBruteforcer
from utils.helpers import save_to_file
from config.constants import JWT_ALGORITHMS

class EvilJWTGUI:
    def __init__(self, master):
        self.master = master
        master.title("EVIL_JWT_FORCE")
        master.geometry("500x350")
        master.configure(bg="#1e1e1e")

        # Configuração do estilo dos botões
        self.configure_styles()

        # Nome do programa
        self.title_label = tk.Label(master, text="🔥 EVIL_JWT_FORCE 🔥", fg="orange", bg="#1e1e1e", font=("Arial", 18, "bold"))
        self.title_label.pack(pady=20)

        # Frame para os botões
        button_frame = tk.Frame(master, bg="#1e1e1e")
        button_frame.pack(pady=10)

        # Botões
        self.create_buttons(button_frame)

    def configure_styles(self):
        # Configuração de estilo para os botões
        style = ttk.Style()
        style.configure("Custom.TButton",
                       padding=10,
                       font=("Arial", 12))

    def create_buttons(self, frame):
        # Botão: Modo Automático
        self.auto_button = tk.Button(frame,
                                   text="Modo Automático",
                                   command=self.run_auto_mode,
                                   width=25,
                                   bg="#444",
                                   fg="white",
                                   font=("Arial", 12),
                                   activebackground="#666",
                                   activeforeground="white")
        self.auto_button.pack(pady=10)

        # Botão: Modo Manual
        self.manual_button = tk.Button(frame,
                                     text="Modo Manual",
                                     command=self.run_manual_mode,
                                     width=25,
                                     bg="#444",
                                     fg="white",
                                     font=("Arial", 12),
                                     activebackground="#666",
                                     activeforeground="white")
        self.manual_button.pack(pady=10)

        # Botão: Sair
        self.quit_button = tk.Button(frame,
                                   text="Sair",
                                   command=self.master.quit,
                                   width=25,
                                   bg="#aa0000",
                                   fg="white",
                                   font=("Arial", 12, "bold"),
                                   activebackground="#cc0000",
                                   activeforeground="white")
        self.quit_button.pack(pady=20)

    def run_auto_mode(self):
        self.execute_cli("--auto")

    def run_manual_mode(self):
        self.execute_cli("--manual")

    def execute_cli(self, mode_flag):
        cli_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "../core/cli.py"))

        if not os.path.exists(cli_path):
            messagebox.showerror("Erro", f"Arquivo CLI não encontrado: {cli_path}")
            return

        try:
            subprocess.Popen([sys.executable, cli_path, mode_flag])
            messagebox.showinfo("Execução", f"Módulo {mode_flag.replace('--', '').capitalize()} iniciado com sucesso!")
        except Exception as e:
            messagebox.showerror("Erro", f"Falha ao executar CLI: {str(e)}")

class StepByStepGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("EVIL JWT FORCE - Manual Mode")
        self.root.geometry("800x600")
        
        # Store user inputs across steps
        self.user_inputs = {}
        self.current_step = 0
        
        # Configure style
        style = ttk.Style()
        style.configure("Title.TLabel", font=("Helvetica", 16, "bold"))
        style.configure("Step.TLabel", font=("Helvetica", 12))
        
        # Create main frame
        self.main_frame = ttk.Frame(self.root, padding="20")
        self.main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Initialize steps
        self.steps = [
            self.create_target_step,
            self.create_algorithm_step,
            self.create_payload_step,
            self.create_wordlist_step,
            self.create_confirmation_step
        ]
        
        # Create navigation buttons
        self.btn_frame = ttk.Frame(self.main_frame)
        self.btn_frame.grid(row=1, column=0, pady=20)
        
        self.prev_btn = ttk.Button(self.btn_frame, text="Previous", command=self.prev_step)
        self.prev_btn.grid(row=0, column=0, padx=5)
        
        self.next_btn = ttk.Button(self.btn_frame, text="Next", command=self.next_step)
        self.next_btn.grid(row=0, column=1, padx=5)
        
        # Show first step
        self.show_step(0)
    
    def create_target_step(self) -> ttk.Frame:
        frame = ttk.Frame(self.main_frame)
        
        # Title
        title = ttk.Label(frame, text="Step 1: Target Configuration", style="Title.TLabel")
        title.grid(row=0, column=0, pady=(0, 20))
        
        # Target URL
        ttk.Label(frame, text="Target URL:", style="Step.TLabel").grid(row=1, column=0, pady=5)
        self.url_entry = ttk.Entry(frame, width=50)
        self.url_entry.grid(row=2, column=0, pady=5)
        if 'target_url' in self.user_inputs:
            self.url_entry.insert(0, self.user_inputs['target_url'])
            
        # Proxy Configuration
        ttk.Label(frame, text="Proxy (optional):", style="Step.TLabel").grid(row=3, column=0, pady=5)
        self.proxy_entry = ttk.Entry(frame, width=50)
        self.proxy_entry.grid(row=4, column=0, pady=5)
        if 'proxy' in self.user_inputs:
            self.proxy_entry.insert(0, self.user_inputs['proxy'])
        
        return frame
    
    def create_algorithm_step(self) -> ttk.Frame:
        frame = ttk.Frame(self.main_frame)
        
        # Title
        title = ttk.Label(frame, text="Step 2: JWT Algorithm Selection", style="Title.TLabel")
        title.grid(row=0, column=0, pady=(0, 20))
        
        # Algorithm Selection
        ttk.Label(frame, text="Select JWT Algorithm:", style="Step.TLabel").grid(row=1, column=0, pady=5)
        self.algo_var = tk.StringVar(value=self.user_inputs.get('algorithm', 'HS256'))
        for i, algo in enumerate(JWT_ALGORITHMS):
            ttk.Radiobutton(frame, text=algo, variable=self.algo_var, value=algo).grid(row=i+2, column=0, pady=2)
        
        return frame
    
    def create_payload_step(self) -> ttk.Frame:
        frame = ttk.Frame(self.main_frame)
        
        # Title
        title = ttk.Label(frame, text="Step 3: JWT Payload Configuration", style="Title.TLabel")
        title.grid(row=0, column=0, pady=(0, 20))
        
        # Payload Editor
        ttk.Label(frame, text="Enter JWT Payload (JSON):", style="Step.TLabel").grid(row=1, column=0, pady=5)
        self.payload_text = tk.Text(frame, width=50, height=10)
        self.payload_text.grid(row=2, column=0, pady=5)
        
        default_payload = {
            "sub": "1234567890",
            "name": "Test User",
            "iat": 1516239022
        }
        
        if 'payload' in self.user_inputs:
            self.payload_text.insert('1.0', json.dumps(self.user_inputs['payload'], indent=2))
        else:
            self.payload_text.insert('1.0', json.dumps(default_payload, indent=2))
        
        return frame
    
    def create_wordlist_step(self) -> ttk.Frame:
        frame = ttk.Frame(self.main_frame)
        
        # Title
        title = ttk.Label(frame, text="Step 4: Wordlist Configuration", style="Title.TLabel")
        title.grid(row=0, column=0, pady=(0, 20))
        
        # Wordlist Options
        ttk.Label(frame, text="Select Wordlist Source:", style="Step.TLabel").grid(row=1, column=0, pady=5)
        
        self.wordlist_var = tk.StringVar(value=self.user_inputs.get('wordlist_type', 'default'))
        ttk.Radiobutton(frame, text="Use Default Wordlist", variable=self.wordlist_var, 
                       value="default").grid(row=2, column=0, pady=2)
        ttk.Radiobutton(frame, text="Custom Wordlist", variable=self.wordlist_var, 
                       value="custom").grid(row=3, column=0, pady=2)
        
        ttk.Label(frame, text="Custom Wordlist Path (optional):", style="Step.TLabel").grid(row=4, column=0, pady=5)
        self.wordlist_entry = ttk.Entry(frame, width=50)
        self.wordlist_entry.grid(row=5, column=0, pady=5)
        if 'wordlist_path' in self.user_inputs:
            self.wordlist_entry.insert(0, self.user_inputs['wordlist_path'])
        
        return frame
    
    def create_confirmation_step(self) -> ttk.Frame:
        frame = ttk.Frame(self.main_frame)
        
        # Title
        title = ttk.Label(frame, text="Step 5: Confirmation", style="Title.TLabel")
        title.grid(row=0, column=0, pady=(0, 20))
        
        # Summary
        summary_text = tk.Text(frame, width=50, height=15, wrap=tk.WORD)
        summary_text.grid(row=1, column=0, pady=5)
        summary_text.insert('1.0', self.get_summary())
        summary_text.config(state='disabled')
        
        # Start Button
        self.start_btn = ttk.Button(frame, text="Start Attack", command=self.start_attack)
        self.start_btn.grid(row=2, column=0, pady=20)
        
        return frame
    
    def get_summary(self) -> str:
        summary = "Attack Configuration Summary:\n\n"
        summary += f"Target URL: {self.user_inputs.get('target_url', 'Not set')}\n"
        summary += f"Proxy: {self.user_inputs.get('proxy', 'None')}\n"
        summary += f"Algorithm: {self.user_inputs.get('algorithm', 'HS256')}\n"
        summary += f"Wordlist: {self.user_inputs.get('wordlist_type', 'default')}\n"
        if self.user_inputs.get('wordlist_type') == 'custom':
            summary += f"Wordlist Path: {self.user_inputs.get('wordlist_path', 'Not set')}\n"
        return summary
    
    def show_step(self, step_num: int):
        # Clear current step
        for widget in self.main_frame.winfo_children():
            if widget != self.btn_frame:
                widget.destroy()
        
        # Show new step
        frame = self.steps[step_num]()
        frame.grid(row=0, column=0)
        
        # Update button states
        self.prev_btn.config(state='normal' if step_num > 0 else 'disabled')
        self.next_btn.config(text="Start" if step_num == len(self.steps)-1 else "Next")
    
    def save_current_step(self):
        if self.current_step == 0:
            self.user_inputs['target_url'] = self.url_entry.get()
            self.user_inputs['proxy'] = self.proxy_entry.get()
        elif self.current_step == 1:
            self.user_inputs['algorithm'] = self.algo_var.get()
        elif self.current_step == 2:
            try:
                payload_text = self.payload_text.get('1.0', tk.END).strip()
                self.user_inputs['payload'] = json.loads(payload_text)
            except json.JSONDecodeError:
                messagebox.showerror("Error", "Invalid JSON payload")
                return False
        elif self.current_step == 3:
            self.user_inputs['wordlist_type'] = self.wordlist_var.get()
            self.user_inputs['wordlist_path'] = self.wordlist_entry.get()
        return True
    
    def next_step(self):
        if not self.save_current_step():
            return
        
        if self.current_step < len(self.steps) - 1:
            self.current_step += 1
            self.show_step(self.current_step)
    
    def prev_step(self):
        if self.current_step > 0:
            self.current_step -= 1
            self.show_step(self.current_step)
    
    def start_attack(self):
        if not self.save_current_step():
            return
            
        # Save configuration
        config = {
            "target_url": self.user_inputs['target_url'],
            "proxy": self.user_inputs['proxy'] if self.user_inputs['proxy'] else None,
            "algorithm": self.user_inputs['algorithm'],
            "payload": self.user_inputs['payload'],
            "wordlist": {
                "type": self.user_inputs['wordlist_type'],
                "path": self.user_inputs['wordlist_path'] if self.user_inputs['wordlist_type'] == 'custom' else None
            }
        }
        
        save_to_file("config/manual_config.json", json.dumps(config, indent=2))
        
        # Start the attack
        try:
            bruteforcer = JWTBruteforcer(config)
            bruteforcer.start()
            messagebox.showinfo("Success", "Attack started successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start attack: {str(e)}")

def launch_gui():
    root = tk.Tk()
    app = EvilJWTGUI(root)
    root.mainloop()

if __name__ == "__main__":
    launch_gui()
    app = StepByStepGUI(root)
    root.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    app = EvilJWTGUI(root)
    root.mainloop()
    app = StepByStepGUI(root)
    root.mainloop()
