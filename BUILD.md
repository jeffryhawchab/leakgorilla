# Building LeakGorilla .deb Package

## On Linux/Kali:

```bash
# 1. Set permissions
chmod 755 debian/DEBIAN/postinst
chmod 755 debian/usr/bin/leakgorilla

# 2. Build package
dpkg-deb --build debian leakgorilla_1.0.0_all.deb

# 3. Install
sudo dpkg -i leakgorilla_1.0.0_all.deb
sudo apt-get install -f
```

## Installation for Users:

### Download .deb from GitHub Releases
```bash
wget https://github.com/jeffryhawchab/leakgorilla/releases/download/v1.0.0/leakgorilla_1.0.0_all.deb
sudo dpkg -i leakgorilla_1.0.0_all.deb
sudo apt-get install -f
```

## To Submit to Kali Official Repos:

1. Visit https://bugs.kali.org/
2. Create account
3. Submit package request with .deb file
4. Wait for Kali team approval

## Package Structure:
```
debian/
├── DEBIAN/
│   ├── control          # Package metadata
│   └── postinst         # Post-installation script
└── usr/
    ├── bin/
    │   └── leakgorilla  # Executable wrapper
    └── share/
        ├── leakgorilla/
        │   └── scanner.py
        └── doc/
            └── leakgorilla/
                ├── README.md
                └── copyright
```
