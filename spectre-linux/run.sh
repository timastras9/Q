#!/bin/bash
#
# Spectre Linux Docker Runner
# ============================
# Quick way to run Spectre Linux in a container
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPECTRE_DIR="${SCRIPT_DIR}/../spectre"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                    Spectre Linux                             ║"
    echo "║               Docker Test Environment                         ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  start      - Start Spectre Linux container"
    echo "  stop       - Stop the container"
    echo "  shell      - Get a shell in the running container"
    echo "  logs       - View container logs"
    echo "  lab        - Start with vulnerable test targets"
    echo "  build      - Rebuild the container image"
    echo "  clean      - Remove containers and images"
    echo ""
}

check_spectre() {
    if [ ! -f "${SPECTRE_DIR}/daemon.py" ]; then
        echo -e "${RED}Error: Spectre daemon not found at ${SPECTRE_DIR}${NC}"
        echo "Make sure the spectre folder exists with daemon.py"
        exit 1
    fi
}

# Load API key from spectre .env if available
load_env() {
    if [ -f "${SPECTRE_DIR}/.env" ]; then
        export $(grep -v '^#' "${SPECTRE_DIR}/.env" | xargs)
        echo -e "${GREEN}[+] Loaded API key from spectre/.env${NC}"
    fi
}

start_spectre() {
    banner
    check_spectre
    load_env

    echo -e "${GREEN}[*] Building Spectre Linux container...${NC}"

    # Create spectre symlink in docker context if needed
    mkdir -p "${SCRIPT_DIR}/docker/spectre"
    cp -r "${SPECTRE_DIR}"/* "${SCRIPT_DIR}/docker/spectre/" 2>/dev/null || true

    cd "${SCRIPT_DIR}/docker"

    # Build and run
    docker-compose up -d --build spectre-linux

    echo ""
    echo -e "${GREEN}[+] Spectre Linux is running!${NC}"
    echo ""
    echo "To access the container:"
    echo -e "  ${CYAN}docker exec -it spectre-linux /bin/bash${NC}"
    echo ""
    echo "Or use this script:"
    echo -e "  ${CYAN}$0 shell${NC}"
    echo ""
}

start_lab() {
    banner
    check_spectre
    load_env

    echo -e "${GREEN}[*] Starting Spectre Linux with vulnerable lab targets...${NC}"

    mkdir -p "${SCRIPT_DIR}/docker/spectre"
    cp -r "${SPECTRE_DIR}"/* "${SCRIPT_DIR}/docker/spectre/" 2>/dev/null || true

    cd "${SCRIPT_DIR}/docker"

    docker-compose --profile lab up -d --build

    echo ""
    echo -e "${GREEN}[+] Spectre Linux lab environment running!${NC}"
    echo ""
    echo "Available targets:"
    echo "  - spectre-test-redis (Redis without auth)"
    echo "  - spectre-test-mongo (MongoDB without auth)"
    echo "  - spectre-test-mysql (MySQL with weak password)"
    echo ""
    echo "Access Spectre Linux:"
    echo -e "  ${CYAN}docker exec -it spectre-linux /bin/bash${NC}"
    echo ""
}

stop_spectre() {
    echo -e "${YELLOW}[*] Stopping Spectre Linux...${NC}"
    cd "${SCRIPT_DIR}/docker"
    docker-compose --profile lab down
    echo -e "${GREEN}[+] Stopped${NC}"
}

shell_spectre() {
    if docker ps | grep -q spectre-linux; then
        docker exec -it spectre-linux /bin/bash
    else
        echo -e "${RED}Spectre Linux container is not running${NC}"
        echo "Start it with: $0 start"
    fi
}

logs_spectre() {
    docker logs -f spectre-linux
}

build_spectre() {
    banner
    check_spectre

    echo -e "${GREEN}[*] Rebuilding Spectre Linux image...${NC}"

    mkdir -p "${SCRIPT_DIR}/docker/spectre"
    cp -r "${SPECTRE_DIR}"/* "${SCRIPT_DIR}/docker/spectre/" 2>/dev/null || true

    cd "${SCRIPT_DIR}/docker"
    docker-compose build --no-cache spectre-linux

    echo -e "${GREEN}[+] Build complete${NC}"
}

clean_spectre() {
    echo -e "${YELLOW}[*] Cleaning up Spectre Linux containers and images...${NC}"

    cd "${SCRIPT_DIR}/docker"
    docker-compose --profile lab down -v --rmi local 2>/dev/null || true
    docker rm -f spectre-linux 2>/dev/null || true

    # Clean up copied files
    rm -rf "${SCRIPT_DIR}/docker/spectre"

    echo -e "${GREEN}[+] Cleaned${NC}"
}

case "${1:-start}" in
    start)
        start_spectre
        ;;
    stop)
        stop_spectre
        ;;
    shell)
        shell_spectre
        ;;
    logs)
        logs_spectre
        ;;
    lab)
        start_lab
        ;;
    build)
        build_spectre
        ;;
    clean)
        clean_spectre
        ;;
    help|--help|-h)
        banner
        usage
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        usage
        exit 1
        ;;
esac
