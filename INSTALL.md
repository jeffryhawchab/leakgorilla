# Installation Guide

## Kali Linux / Debian / Ubuntu

### Download and Install

```bash
# Download the .deb package
wget https://github.com/jeffryhawchab/leakgorilla/releases/download/v1.0.0/leakgorilla_1.0.0_all.deb

# Install
sudo dpkg -i leakgorilla_1.0.0_all.deb
sudo apt-get install -f
```

### Verify Installation

```bash
leakgorilla --help
```

### Build Your Own Package

```bash
git clone https://github.com/jeffryhawchab/leakgorilla.git
cd leakgorilla
chmod +x build-deb.sh
./build-deb.sh
```

## Requirements

- Python 3.6+
- python3-requests
- python3-bs4

Dependencies are automatically installed with the .deb package.
