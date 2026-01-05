#!/bin/bash
#
# Sentinel Linux Docker Runner
# ============================
# Quick way to run Sentinel Linux in a container
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENTINEL_DIR="${SCRIPT_DIR}/../sentinel"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                    Sentinel Linux                             ║"
    echo "║               Docker Test Environment                         ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

usage() {
    echo "Usage: $0 [command]"
    echo ""
    echo "Commands:"
    echo "  start      - Start Sentinel Linux container"
    echo "  stop       - Stop the container"
    echo "  shell      - Get a shell in the running container"
    echo "  logs       - View container logs"
    echo "  lab        - Start with vulnerable test targets"
    echo "  build      - Rebuild the container image"
    echo "  clean      - Remove containers and images"
    echo ""
}

check_sentinel() {
    if [ ! -f "${SENTINEL_DIR}/daemon.py" ]; then
        echo -e "${RED}Error: Sentinel daemon not found at ${SENTINEL_DIR}${NC}"
        echo "Make sure the sentinel folder exists with daemon.py"
        exit 1
    fi
}

# Load API key from sentinel .env if available
load_env() {
    if [ -f "${SENTINEL_DIR}/.env" ]; then
        export $(grep -v '^#' "${SENTINEL_DIR}/.env" | xargs)
        echo -e "${GREEN}[+] Loaded API key from sentinel/.env${NC}"
    fi
}

start_sentinel() {
    banner
    check_sentinel
    load_env

    echo -e "${GREEN}[*] Building Sentinel Linux container...${NC}"

    # Create sentinel symlink in docker context if needed
    mkdir -p "${SCRIPT_DIR}/docker/sentinel"
    cp -r "${SENTINEL_DIR}"/* "${SCRIPT_DIR}/docker/sentinel/" 2>/dev/null || true

    cd "${SCRIPT_DIR}/docker"

    # Build and run
    docker-compose up -d --build sentinel-linux

    echo ""
    echo -e "${GREEN}[+] Sentinel Linux is running!${NC}"
    echo ""
    echo "To access the container:"
    echo -e "  ${CYAN}docker exec -it sentinel-linux /bin/bash${NC}"
    echo ""
    echo "Or use this script:"
    echo -e "  ${CYAN}$0 shell${NC}"
    echo ""
}

start_lab() {
    banner
    check_sentinel
    load_env

    echo -e "${GREEN}[*] Starting Sentinel Linux with vulnerable lab targets...${NC}"

    mkdir -p "${SCRIPT_DIR}/docker/sentinel"
    cp -r "${SENTINEL_DIR}"/* "${SCRIPT_DIR}/docker/sentinel/" 2>/dev/null || true

    cd "${SCRIPT_DIR}/docker"

    docker-compose --profile lab up -d --build

    echo ""
    echo -e "${GREEN}[+] Sentinel Linux lab environment running!${NC}"
    echo ""
    echo "Available targets:"
    echo "  - sentinel-test-redis (Redis without auth)"
    echo "  - sentinel-test-mongo (MongoDB without auth)"
    echo "  - sentinel-test-mysql (MySQL with weak password)"
    echo ""
    echo "Access Sentinel Linux:"
    echo -e "  ${CYAN}docker exec -it sentinel-linux /bin/bash${NC}"
    echo ""
}

stop_sentinel() {
    echo -e "${YELLOW}[*] Stopping Sentinel Linux...${NC}"
    cd "${SCRIPT_DIR}/docker"
    docker-compose --profile lab down
    echo -e "${GREEN}[+] Stopped${NC}"
}

shell_sentinel() {
    if docker ps | grep -q sentinel-linux; then
        docker exec -it sentinel-linux /bin/bash
    else
        echo -e "${RED}Sentinel Linux container is not running${NC}"
        echo "Start it with: $0 start"
    fi
}

logs_sentinel() {
    docker logs -f sentinel-linux
}

build_sentinel() {
    banner
    check_sentinel

    echo -e "${GREEN}[*] Rebuilding Sentinel Linux image...${NC}"

    mkdir -p "${SCRIPT_DIR}/docker/sentinel"
    cp -r "${SENTINEL_DIR}"/* "${SCRIPT_DIR}/docker/sentinel/" 2>/dev/null || true

    cd "${SCRIPT_DIR}/docker"
    docker-compose build --no-cache sentinel-linux

    echo -e "${GREEN}[+] Build complete${NC}"
}

clean_sentinel() {
    echo -e "${YELLOW}[*] Cleaning up Sentinel Linux containers and images...${NC}"

    cd "${SCRIPT_DIR}/docker"
    docker-compose --profile lab down -v --rmi local 2>/dev/null || true
    docker rm -f sentinel-linux 2>/dev/null || true

    # Clean up copied files
    rm -rf "${SCRIPT_DIR}/docker/sentinel"

    echo -e "${GREEN}[+] Cleaned${NC}"
}

case "${1:-start}" in
    start)
        start_sentinel
        ;;
    stop)
        stop_sentinel
        ;;
    shell)
        shell_sentinel
        ;;
    logs)
        logs_sentinel
        ;;
    lab)
        start_lab
        ;;
    build)
        build_sentinel
        ;;
    clean)
        clean_sentinel
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
