
#!/usr/bin/env python3
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="Senv",
    version="1.0.0",
    author="Mohammad Hosseini",

    author_email="noting@noting.com",
    description="A comprehensive, secure and advanced library for managing .env files",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mohammadamin382/Senv_library.git",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=[
        "cryptography>=38.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=22.0.0",
            "flake8>=4.0.0",
            "mypy>=0.900",
            "isort>=5.0.0",
        ],
        "test": [
            "pytest>=7.0.0",
            "pytest-cov>=3.0.0",
        ],
        "advanced": [
            "argon2-cffi>=21.0.0",
            "zxcvbn>=4.4.28",
            "pyotp>=2.8.0"
        ]
    },
    keywords="dotenv, environment, security, encryption, configuration, secrets, senv",
    project_urls={
        "Bug Tracker": "https://github.com/mohammadamin382/Senv_library/issues",
        "Documentation": "https://github.com/mohammadamin382/Senv_library",
        "Source Code": "https://github.com/mohammadamin382/Senv_library",
    },
)
