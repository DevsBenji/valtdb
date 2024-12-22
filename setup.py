"""
Setup configuration for ValtDB
"""
from setuptools import setup, find_packages
import os

# Read README for long description
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="valtdb",
    version="1.0.0",
    author="DevsBenji",
    author_email="benji.development@protonmail.com",
    description="A secure and flexible database library with encryption and remote access",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/DevsBenji/valtdb",
    project_urls={
        "Bug Tracker": "https://github.com/DevsBenji/valtdb/issues",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Database",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    keywords=[
        "database",
        "encryption",
        "secure-database",
        "nosql",
        "embedded-database",
        "key-value-store",
        "document-database",
        "database-security",
        "encrypted-storage",
        "secure-communication",
        "database-tools",
        "python3",
        "data-storage",
        "crypto",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=41.0.0",
        "paramiko>=3.3.1",
        "python-dateutil>=2.8.2",
        "requests>=2.31.0",
        "typing-extensions>=4.7.1",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.7.0",
            "isort>=5.12.0",
            "mypy>=1.5.0",
            "flake8>=6.1.0",
            "bandit>=1.7.5",
        ],
        "docs": [
            "sphinx>=4.0.2",
            "sphinx-rtd-theme>=0.5.2",
            "sphinx-autodoc-typehints>=1.12.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "valtdb-cli=valtdb.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
