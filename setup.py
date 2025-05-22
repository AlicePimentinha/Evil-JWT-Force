from setuptools import setup, find_packages

setup(
    name='EVIL_JWT_FORCE',
    version='1.0.0',
    description='Ferramenta automatizada para força bruta e análise ofensiva de JWTs',
    long_description='Ferramenta acadêmica para exploração de falhas JWT, incluindo brute-force, descriptografia AES, SQLi e automação ofensiva.',
    author='Equipe EVIL_JWT_FORCE',
    author_email='contato@eviljwtforce.dev',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'requests>=2.25.0',
        'pyjwt>=2.4.0',
        'termcolor',
        'colorama',
        'cryptography>=3.4.7',
        'beautifulsoup4>=4.9.3',
        'lxml',
        'fake-useragent>=1.5.1',
        'httpx>=0.24.0',
        'tkinter',
        'pyyaml'
    ],
    entry_points={
        'console_scripts': [
            'evil-jwt=main:main',
        ],
    },
    python_requires='>=3.8',
)
