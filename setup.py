#!/usr/bin/env python3
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="leakgorilla",
    version="1.0.0",
    author="Jeffrey Hawchab",
    description="Advanced web secret scanner for detecting API keys and credentials",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jeffryhawchab/leakgorilla",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
    ],
    python_requires=">=3.6",
    install_requires=[
        "requests>=2.25.0",
        "beautifulsoup4>=4.9.0",
    ],
    entry_points={
        "console_scripts": [
            "leakgorilla=leakgorilla.scanner:main",
        ],
    },
)
