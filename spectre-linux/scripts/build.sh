#!/bin/bash
#
# Spectre Linux Build Script
# ===========================
# Builds Spectre Linux ISO from scratch
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Load configuration
source "${PROJECT_ROOT}/config/build.conf"

banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════╗"
    echo "║           Spectre Linux Build System                     ║"
    echo "║           Version: ${SPECTRE_VERSION}                              ║"
    echo "╚═══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

log() {
    echo -e "${GREEN}[BUILD]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

check_requirements() {
    log "Checking build requirements..."

    if ! command -v docker &> /dev/null; then
        error "Docker is required but not installed"
    fi

    log "Requirements satisfied"
}

build_in_docker() {
    log "Building Spectre Linux in Docker container..."

    # Create build Dockerfile
    cat > "${PROJECT_ROOT}/build/Dockerfile.build" << 'DOCKERFILE'
FROM alpine:3.19

# Install build dependencies
RUN apk add --no-cache \
    build-base \
    linux-headers \
    ncurses-dev \
    openssl-dev \
    bc \
    flex \
    bison \
    elfutils-dev \
    perl \
    python3 \
    py3-pip \
    xorriso \
    grub \
    grub-bios \
    grub-efi \
    mtools \
    dosfstools \
    squashfs-tools \
    cpio \
    wget \
    curl \
    git \
    xz

WORKDIR /build
DOCKERFILE

    docker build -t spectre-builder -f "${PROJECT_ROOT}/build/Dockerfile.build" "${PROJECT_ROOT}/build"

    log "Running build container..."
    docker run --rm -it \
        -v "${PROJECT_ROOT}:/spectre-linux" \
        -v "${PROJECT_ROOT}/build/cache:/cache" \
        spectre-builder \
        /spectre-linux/scripts/build-internal.sh
}

main() {
    banner
    check_requirements

    mkdir -p "${PROJECT_ROOT}/build/cache"
    mkdir -p "${PROJECT_ROOT}/iso"

    build_in_docker

    log "Build complete!"
    echo -e "${GREEN}ISO available at: ${PROJECT_ROOT}/iso/spectre-linux-${SPECTRE_VERSION}.iso${NC}"
}

main "$@"
