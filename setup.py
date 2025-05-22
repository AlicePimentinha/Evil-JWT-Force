from setuptools import setup, find_packages
from setuptools.command.install import install
import shutil
import os
import sys
import shutil
import subprocess

class CustomInstallCommand(install):
    def run(self):
        install.run(self)
        # Caminho absoluto do .bat na raiz do projeto
        bat_src = os.path.join(os.path.dirname(__file__), "EVIL_JWT_FORCE.bat")
        if hasattr(sys, 'real_prefix'):  # virtualenv
            scripts_dir = os.path.join(sys.prefix, 'Scripts')
        else:
            scripts_dir = os.path.join(sys.base_prefix, 'Scripts')
        bat_dst = os.path.join(scripts_dir, "EVIL_JWT_FORCE.bat")
        try:
            shutil.copyfile(bat_src, bat_dst)
            print(f"Arquivo .bat copiado para {bat_dst}")
        except Exception as e:
            print(f"Falha ao copiar o .bat: {e}")
        # Removido: comandos perigosos do sistema

setup(
    name="EVIL_JWT_FORCE",
    version="1.0.0",
    description="Ferramenta de Teste de Segurança JWT",
    author="EVIL_JWT_FORCE Team",
    packages=find_packages(
        include=[
            "core",
            "core.*",
            "modules",
            "modules.*",
            "utils",
            "utils.*",
            "config",
            "config.*",
            "output",
            "output.*",
            "logs",
            "logs.*",
            "reports",
            "reports.*",
            "scripts",
            "scripts.*",
            "gui",
            "gui.*"
        ]
    ),
    include_package_data=True,
    install_requires=[
        "pyjwt>=2.4.0",
        "termcolor",
        "colorama",
        "cryptography>=3.4.7",
        "beautifulsoup4>=4.9.3",
        "lxml",
        "fake-useragent>=1.5.1",
        "httpx>=0.24.0",
        "pyyaml",
        "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
        "aiohttp",
        "requests",
        "pytest",
        "Pillow",  # Manipulação de imagens na GUI
        "tabulate",  # Exibição de tabelas no terminal
        "rich",      # Logs coloridos e outputs avançados
        "pyinstaller",  # Empacotamento
        "pyperclip",    # Área de transferência
        "validators",   # Validação de URLs/emails
        "requests[socks]",  # Proxy SOCKS
        "openpyxl",     # Exportação para Excel
        "reportlab"     # Relatórios PDF
    ],
    python_requires=">=3.7",
    entry_points={
        'console_scripts': [
            'evil-jwt=main:main',
        ],
    },
    cmdclass={
        'install': CustomInstallCommand,
    },
)

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
    "nova_dependencia"
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},
)
python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},
)
python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
},

python_requires='>=3.8',
install_requires=[
    "pyjwt>=2.4.0",
    "termcolor",
    "colorama",
    "cryptography>=3.4.7",
    "beautifulsoup4>=4.9.3",
    "lxml",
    "fake-useragent>=1.5.1",
    "httpx>=0.24.0",
    "pyyaml",
    "tk",  # Para interface gráfica Tkinter (em alguns ambientes pode ser necessário)
    "aiohttp",
    "requests",
    "pytest",
    "Pillow",  # Manipulação de imagens na GUI
    "tabulate",  # Exibição de tabelas no terminal
    "rich",      # Logs coloridos e outputs avançados
    "pyinstaller",  # Empacotamento
    "pyperclip",    # Área de transferência
    "validators",   # Validação de URLs/emails
    "requests[socks]",  # Proxy SOCKS
    "openpyxl",     # Exportação para Excel
    "reportlab"     # Relatórios PDF
],
python_requires=">=3.7",
entry_points={
    'console_scripts': [
        'evil-jwt=main:main',
    ],
},
cmdclass={
    'install': CustomInstallCommand,
}
