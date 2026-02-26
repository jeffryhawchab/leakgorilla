# How to Get LeakGorilla into Kali Linux Official Repositories

## Option 1: Submit to Kali Linux (Official)

1. **Build the package:**
   ```bash
   ./build-deb.sh
   ```

2. **Test the package:**
   ```bash
   sudo dpkg -i leakgorilla_1.0.0_all.deb
   leakgorilla --help
   ```

3. **Submit to Kali:**
   - Visit: https://bugs.kali.org/
   - Create account and submit package request
   - Provide: package description, .deb file, GitHub repo
   - Wait for Kali team review (can take weeks/months)

## Option 2: Host Your Own APT Repository

1. **Create repository structure:**
   ```bash
   mkdir -p myrepo/pool/main
   cp leakgorilla_1.0.0_all.deb myrepo/pool/main/
   ```

2. **Generate Packages file:**
   ```bash
   cd myrepo
   dpkg-scanpackages pool/main /dev/null | gzip -9c > pool/main/Packages.gz
   ```

3. **Host on GitHub Pages or web server**

4. **Users add your repo:**
   ```bash
   echo "deb [trusted=yes] https://yourdomain.com/myrepo pool main" | sudo tee /etc/apt/sources.list.d/leakgorilla.list
   sudo apt update
   sudo apt install leakgorilla
   ```

## Option 3: GitHub Releases (Current Method)

1. **Create GitHub release with .deb file**
2. **Users download and install:**
   ```bash
   wget https://github.com/jeffryhawchab/leakgorilla/releases/download/v1.0.0/leakgorilla_1.0.0_all.deb
   sudo dpkg -i leakgorilla_1.0.0_all.deb
   sudo apt-get install -f
   ```

## Current Status

Users can download .deb from GitHub releases and install with `sudo dpkg -i leakgorilla_1.0.0_all.deb`
