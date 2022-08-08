#!/usr/bin/env bash
set -euo pipefail

openssl genrsa -out "$1" 4096
openssl rsa -in "$1" -out "$2" -pubout -outform PEM
