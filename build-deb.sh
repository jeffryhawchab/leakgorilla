#!/bin/bash

echo "Building LeakGorilla Debian package..."

# Set permissions
chmod 755 debian/DEBIAN/postinst
chmod 755 debian/usr/bin/leakgorilla

# Build the package
dpkg-deb --build debian leakgorilla_1.0.0_all.deb

echo ""
echo "✓ Package built: leakgorilla_1.0.0_all.deb"
echo ""
echo "To install:"
echo "  sudo dpkg -i leakgorilla_1.0.0_all.deb"
echo "  sudo apt-get install -f  # Fix dependencies if needed"
echo ""
echo "To add to Kali repository, contact Kali team or host on your own repo"
