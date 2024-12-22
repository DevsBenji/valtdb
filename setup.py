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
    author_email="DevsBenji@valtdb.com",
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
        'cryptography>=3.4.7',
        'paramiko>=2.8.1',  # For SSH support
        'bcrypt>=3.2.0',    # For password hashing
        'PyJWT>=2.3.0',     # For JWT tokens
        'argon2-cffi>=21.3.0',  # For Argon2 password hashing
        'pynacl>=1.4.0',    # For ChaCha20 support
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=2.12.1",
            "pytest-benchmark>=4.0.0",  # For performance testing
            "black>=22.3.0",
            "isort>=5.10.1",
            "mypy>=0.950",
            "flake8>=4.0.1",
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