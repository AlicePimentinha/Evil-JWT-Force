#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import argparse

# Garante que o diretório raiz (EVIL_JWT_FORCE) esteja no sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# Imports dos módulos internos
from core import auth, wordlist_generator, bruteforce, aes_decrypt, sql_injector, sentry_simulator
from utils import report

# Banner do sistema
BANNER = r"""
╔══════════════════════════════════════════════════════╗
║              ███████╗██╗   ██╗██╗██╗                 ║
║              ██╔════╝██║   ██║██║██║                 ║
║              █████╗  ██║   ██║██║██║                 ║
║              ██╔══╝  ╚██╗ ██╔╝██║██║                 ║
║              ███████╗ ╚████╔╝ ██║███████╗            ║
║              ╚══════╝  ╚═══╝  ╚═╝╚══════╝            ║
║               EVIL JWT FORCE - CLI Engine            ║
╚══════════════════════════════════════════════════════╝
"""

OPTIONS = {
    "1": "Execução Automática (Modo Full)",
    "2": "Execução Manual (Escolher Etapas)",
    "3": "Sair"
}

def print_menu():
    os.system("clear" if os.name != "nt" else "cls")
    print(BANNER)
    for k, v in OPTIONS.items():
        print(f"[{k}] {v}")
    print()

def run_automatic_mode():
    print("🚀 Executando modo automático completo...\n")
    time.sleep(0.5)

    try:
        auth.run()
        wordlist_generator.run()
        bruteforce.run()
        aes_decrypt.run()
        sql_injector.SQLInjector().run()
        sentry_simulator.run()
        report.generate_html_report()
        print("\n✅ Execução automática finalizada. Relatório salvo em: reports/report.html\n")
    except Exception as e:
        print(f"\n❌ Erro durante a execução automática: {e}")

    input("Pressione Enter para retornar ao menu...")

def run_manual_mode():
    print("\n📦 Módulos disponíveis:")
    steps = {
        "1": ("Autenticação", {
            "1": "JWT (Padrão)",
            "2": "Basic Auth",
            "3": "Bearer Token",
            "4": "API Key",
            "5": "OAuth 2.0",
            "6": "Digest Auth",
            "7": "NTLM",
            "8": "Voltar"
        }),
        "2": ("wordlist_generator.py", wordlist_generator.run),
        "3": ("bruteforce.py", bruteforce.run),
        "4": ("aes_decrypt.py", aes_decrypt.run),
        "5": ("sql_injector.py", lambda: sql_injector.SQLInjector().run()),
        "6": ("sentry_simulator.py", sentry_simulator.run),
        "7": ("report.py", report.generate_html_report),
        "8": ("Voltar", None)
    }

    while True:
        for k, (label, value) in steps.items():
            if isinstance(value, dict):
                print(f"[{k}] {label} (Múltiplos métodos)")
            else:
                print(f"[{k}] {label}")

        choice = input("\nEscolha o módulo a executar: ").strip()
        if choice in steps:
            if choice == "8":
                break
            elif choice == "1":
                print("\nMétodos de Autenticação disponíveis:")
                for k, v in steps["1"][1].items():
                    print(f"[{k}] {v}")
                auth_method = input("\nEscolha o método de autenticação: ").strip()
                if auth_method in steps["1"][1]:
                    if auth_method == "8":
                        continue
                    auth.run(auth_method=steps["1"][1][auth_method].lower().replace(" ", "_"))
            else:
                print(f"\n▶ Executando {steps[choice][0]}...\n")
                try:
                    steps[choice][1]()
                    print(f"✅ {steps[choice][0]} finalizado.\n")
                except Exception as e:
                    print(f"❌ Erro no módulo {steps[choice][0]}: {e}\n")
        else:
            print("❌ Opção inválida. Tente novamente.")

def parse_args():
    parser = argparse.ArgumentParser(description="EVIL_JWT_FORCE CLI")
    parser.add_argument("--auto", action="store_true", help="Executa modo automático")
    parser.add_argument("--manual", action="store_true", help="Executa modo manual")
    return parser.parse_args()

def main():
    args = parse_args()

    if args.auto:
        run_automatic_mode()
        return
    elif args.manual:
        run_manual_mode()
        return

    while True:
        print_menu()
        choice = input("Escolha uma opção: ").strip()

        if choice == "1":
            run_automatic_mode()
        elif choice == "2":
            run_manual_mode()
        elif choice == "3":
            print("\n👋 Encerrando EVIL JWT FORCE...")
            time.sleep(1)
            break
        else:
            print("❌ Opção inválida. Tente novamente.")

if __name__ == "__main__":
    main()
