#!/bin/bash
#
# setup.sh: Downloads, extracts, and builds MySQL dependencies.
# (Version 8.4.7 - No patch)
#

set -e

# --- Configuration ---
CUR_DIR="$( cd "$(dirname "$0")" >/dev/null 2>&1 ; pwd -P )"

# Base directory for all builds, profiles, and source code
DEV_DIR=$(cd ../../../../ipra-run ; pwd)
BENCHMARK_BASE_DIR="${DEV_DIR}/mysql_benchmark"
SOURCE_BASE_DIR="${BENCHMARK_BASE_DIR}/source"

# We assume the 'bootstrapped_clang' build from your other Makefile exists
BOOTSTRAPPED_DIR="${DEV_DIR}/bootstrapped_clang"
NCC="${BOOTSTRAPPED_DIR}/bin/clang"
NCXX="${BOOTSTRAPPED_DIR}/bin/clang++"

# Package Definitions
MYSQL_NAME="mysql-8.4.7"
MYSQL_PACKAGE_NAME="mysql-8.4.7.tar.gz"
MYSQL_SOURCE="${SOURCE_BASE_DIR}/${MYSQL_NAME}"
MYSQL_URL="https://dev.mysql.com/get/Downloads/MySQL-8.4/mysql-8.4.7.tar.gz"

OPENSSL_NAME="openssl-3.0.5"
OPENSSL_PACKAGE_NAME="${OPENSSL_NAME}.tar.gz"
OPENSSL_SOURCE="${SOURCE_BASE_DIR}/${OPENSSL_NAME}"
OPENSSL_URL="https://www.openssl.org/source/${OPENSSL_PACKAGE_NAME}"

NCURSE_NAME="ncurses-6.3"
NCURSE_PACKAGE_NAME="${NCURSE_NAME}.tar.gz"
NCURSE_SOURCE="${SOURCE_BASE_DIR}/${NCURSE_NAME}"
NCURSE_URL="https://ftp.gnu.org/pub/gnu/ncurses/${NCURSE_PACKAGE_NAME}"

NPROC=$(nproc)

echo "--- Setup Started ---"
echo "Source Directory: ${SOURCE_BASE_DIR}"
echo "Compiler: ${NCC}"
mkdir -p "${SOURCE_BASE_DIR}"
cd "${SOURCE_BASE_DIR}"

# --- 1. Download Packages ---
echo "Downloading packages..."
wget -q -N "${MYSQL_URL}"
wget -q -N "${OPENSSL_URL}"
wget -q -N "${NCURSE_URL}"

# --- 2. Build OpenSSL (Dependency) ---
if [ ! -d "${OPENSSL_SOURCE}/install" ]; then
    echo "Building OpenSSL..."
    rm -rf "${OPENSSL_SOURCE}"
    tar xzf "${OPENSSL_PACKAGE_NAME}"
    cd "${OPENSSL_SOURCE}"
    CC="${NCC}" CXX="${NCXX}" ./config no-asm no-shared --prefix="${OPENSSL_SOURCE}/install"
    make depend -j"${NPROC}"
    make -j"${NPROC}"
    make install_sw
    cd "${SOURCE_BASE_DIR}"
else
    echo "OpenSSL already built."
fi

# --- 3. Build ncurses (Dependency) ---
if [ ! -d "${NCURSE_SOURCE}/install" ]; then
    echo "Building ncurses..."
    rm -rf "${NCURSE_SOURCE}"
    tar xzf "${NCURSE_PACKAGE_NAME}"
    cd "${NCURSE_SOURCE}"
    CC="${NCC}" CXX="${NCXX}" ./configure --prefix="${NCURSE_SOURCE}/install"
    make -j"${NPROC}"
    make install
    # Copy the helper CursesConfig.cmake
    cp "${CUR_DIR}/CursesConfig.cmake" "${NCURSE_SOURCE}/install/"
    cd "${SOURCE_BASE_DIR}"
else
    echo "ncurses already built."
fi

# --- 4. Extract MySQL ---
if [ ! -d "${MYSQL_SOURCE}" ]; then
    echo "Extracting MySQL..."
    tar xzf "${MYSQL_PACKAGE_NAME}"
    cd "${SOURCE_BASE_DIR}"
else
    echo "MySQL already extracted."
fi

echo "--- Setup Complete ---"
touch "${SOURCE_BASE_DIR}/.setup_complete"