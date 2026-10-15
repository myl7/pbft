#!/usr/bin/env bash
set -euo pipefail

# OpenSSL 3 defaults to PKCS#8, while the existing Go fixture loader expects
# PKCS#1. Older OpenSSL versions already use PKCS#1 and lack this option.
genrsa_args=()
genrsa_help=$(openssl genrsa -help 2>&1 || true)
if [[ "$genrsa_help" == *-traditional* ]]; then
  genrsa_args+=(-traditional)
fi
openssl genrsa "${genrsa_args[@]}" -out "$1" 4096
openssl rsa -in "$1" -out "$2" -pubout -outform PEM
