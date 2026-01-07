#!/bin/bash
#
# Spectre Linux Internal Build Script
# =====================================
# Runs inside the build container
#

set -e

PROJECT_ROOT="/spectre-linux"
BUILD_ROOT="/tmp/spectre-build"
CACHE_DIR="/cache"

source "${PROJECT_ROOT}/config/build.conf"

# Colors
GREEN='\033[0;32m'
CYAN='\033[0;36m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[BUILD]${NC} $1"
}

step() {
    echo -e "${CYAN}===> $1${NC}"
}

# =============================================================================
# Step 1: Prepare build environment
# =============================================================================
prepare_build() {
    step "Preparing build environment"

    rm -rf "${BUILD_ROOT}"
    mkdir -p "${BUILD_ROOT}"/{rootfs,iso,kernel,initramfs}
    mkdir -p "${CACHE_DIR}"

    cd "${BUILD_ROOT}"
}

# =============================================================================
# Step 2: Build/Download Kernel
# =============================================================================
build_kernel() {
    step "Building Linux kernel ${KERNEL_VERSION}"

    KERNEL_TARBALL="${CACHE_DIR}/linux-${KERNEL_VERSION}.tar.xz"

    if [ ! -f "${KERNEL_TARBALL}" ]; then
        log "Downloading kernel..."
        wget -O "${KERNEL_TARBALL}" "${KERNEL_URL}"
    fi

    cd "${BUILD_ROOT}/kernel"
    tar xf "${KERNEL_TARBALL}" --strip-components=1

    # Use our hardened kernel config
    if [ -f "${PROJECT_ROOT}/kernel/config-spectre" ]; then
        cp "${PROJECT_ROOT}/kernel/config-spectre" .config
    else
        # Generate default config with security options
        make defconfig
        # Enable security features
        ./scripts/config --enable CONFIG_SECURITY
        ./scripts/config --enable CONFIG_SECURITY_SELINUX
        ./scripts/config --enable CONFIG_AUDIT
        ./scripts/config --enable CONFIG_SECCOMP
        ./scripts/config --enable CONFIG_STRICT_KERNEL_RWX
        ./scripts/config --enable CONFIG_FORTIFY_SOURCE
        ./scripts/config --enable CONFIG_STACKPROTECTOR_STRONG
        ./scripts/config --enable CONFIG_RANDOMIZE_BASE
        ./scripts/config --enable CONFIG_RANDOMIZE_MEMORY
        ./scripts/config --disable CONFIG_ACPI_CUSTOM_DSDT
        ./scripts/config --disable CONFIG_COMPAT_BRK
        ./scripts/config --disable CONFIG_DEVKMEM
        ./scripts/config --enable CONFIG_DEBUG_CREDENTIALS
        ./scripts/config --enable CONFIG_DEBUG_NOTIFIERS
        ./scripts/config --enable CONFIG_DEBUG_LIST
        ./scripts/config --enable CONFIG_DEBUG_SG
        ./scripts/config --enable CONFIG_SCHED_STACK_END_CHECK
    fi

    log "Compiling kernel (this may take a while)..."
    make -j$(nproc)

    cp arch/x86/boot/bzImage "${BUILD_ROOT}/vmlinuz"
    log "Kernel built successfully"
}

# =============================================================================
# Step 3: Create root filesystem
# =============================================================================
create_rootfs() {
    step "Creating root filesystem"

    ROOTFS="${BUILD_ROOT}/rootfs"

    # Use Alpine as base for minimal footprint
    log "Installing base system from Alpine..."

    # Download Alpine minirootfs
    ALPINE_ROOTFS="${CACHE_DIR}/alpine-minirootfs-${ALPINE_VERSION}.0-x86_64.tar.gz"
    if [ ! -f "${ALPINE_ROOTFS}" ]; then
        wget -O "${ALPINE_ROOTFS}" \
            "${ALPINE_MIRROR}/v${ALPINE_VERSION}/releases/x86_64/alpine-minirootfs-${ALPINE_VERSION}.0-x86_64.tar.gz"
    fi

    tar xzf "${ALPINE_ROOTFS}" -C "${ROOTFS}"

    # Setup DNS
    cp /etc/resolv.conf "${ROOTFS}/etc/resolv.conf"

    # Install packages using chroot
    log "Installing core packages..."
    chroot "${ROOTFS}" /bin/sh -c "
        apk update
        apk add --no-cache \
            busybox-extras \
            openrc \
            python3 \
            py3-pip \
            py3-requests \
            openssl \
            ca-certificates \
            curl \
            jq \
            iptables \
            iproute2 \
            procps \
            util-linux \
            shadow \
            sudo \
            openssh \
            audit \
            bash \
            nano \
            less \
            nmap
    "

    log "Root filesystem created"
}

# =============================================================================
# Step 4: Install Spectre
# =============================================================================
install_spectre() {
    step "Installing Spectre daemon"

    ROOTFS="${BUILD_ROOT}/rootfs"

    # Create Spectre directories
    mkdir -p "${ROOTFS}/opt/spectre"/{config,data,baseline}
    mkdir -p "${ROOTFS}/etc/spectre"
    mkdir -p "${ROOTFS}/var/log/spectre"
    mkdir -p "${ROOTFS}/var/lib/spectre"

    # Copy Spectre daemon
    cp "${PROJECT_ROOT}/../spectre/daemon.py" "${ROOTFS}/opt/spectre/daemon.py"
    cp "${PROJECT_ROOT}/../spectre/config/spectre.json" "${ROOTFS}/etc/spectre/config.json"
    chmod +x "${ROOTFS}/opt/spectre/daemon.py"

    # Create symlink for config
    ln -sf /etc/spectre/config.json "${ROOTFS}/opt/spectre/config/spectre.json"

    # Install Python dependencies
    chroot "${ROOTFS}" /bin/sh -c "
        pip3 install --no-cache-dir anthropic requests
    "

    # Create OpenRC service
    cat > "${ROOTFS}/etc/init.d/spectre" << 'SERVICE'
#!/sbin/openrc-run

name="spectre"
description="Spectre Security Daemon"
command="/usr/bin/python3"
command_args="/opt/spectre/daemon.py"
pidfile="/run/spectre.pid"
command_background="yes"

depend() {
    need net
    after firewall
}

start_pre() {
    mkdir -p /var/log/spectre
    mkdir -p /var/lib/spectre
}
SERVICE
    chmod +x "${ROOTFS}/etc/init.d/spectre"

    # Enable service
    chroot "${ROOTFS}" /bin/sh -c "
        rc-update add spectre default
    "

    # Create spectrectl command
    cat > "${ROOTFS}/usr/local/bin/spectrectl" << 'SPECTRECTL'
#!/bin/bash
# Spectre Control Utility

case "$1" in
    status)
        rc-service spectre status
        ;;
    start)
        rc-service spectre start
        ;;
    stop)
        rc-service spectre stop
        ;;
    restart)
        rc-service spectre restart
        ;;
    logs)
        tail -f /var/log/spectre/spectre.log
        ;;
    scan)
        shift
        python3 /opt/spectre/daemon.py --scan "$@"
        ;;
    config)
        nano /etc/spectre/config.json
        ;;
    *)
        echo "Spectre Linux Control"
        echo "Usage: spectrectl {status|start|stop|restart|logs|scan|config}"
        ;;
esac
SPECTRECTL
    chmod +x "${ROOTFS}/usr/local/bin/spectrectl"

    log "Spectre installed"
}

# =============================================================================
# Step 5: Configure system
# =============================================================================
configure_system() {
    step "Configuring Spectre Linux"

    ROOTFS="${BUILD_ROOT}/rootfs"

    # Set hostname
    echo "spectre" > "${ROOTFS}/etc/hostname"

    # Configure hosts
    cat > "${ROOTFS}/etc/hosts" << 'HOSTS'
127.0.0.1   localhost spectre
::1         localhost spectre
HOSTS

    # Create /etc/os-release
    cat > "${ROOTFS}/etc/os-release" << OSRELEASE
NAME="Spectre Linux"
VERSION="${SPECTRE_VERSION}"
ID=spectre
ID_LIKE=alpine
VERSION_ID=${SPECTRE_VERSION}
PRETTY_NAME="Spectre Linux ${SPECTRE_VERSION} (${SPECTRE_CODENAME})"
HOME_URL="https://github.com/spectre-sec/spectre-linux"
BUG_REPORT_URL="https://github.com/spectre-sec/spectre-linux/issues"
OSRELEASE

    # Create issue banner
    cat > "${ROOTFS}/etc/issue" << 'ISSUE'

███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

          Spectre Linux - AI-Powered Security
          Version: \v | Kernel: \r | Arch: \m

ISSUE

    # MOTD
    cat > "${ROOTFS}/etc/motd" << 'MOTD'

Welcome to Spectre Linux - Security that thinks for itself.

Quick Start:
  spectrectl status    - Check Spectre daemon status
  spectrectl logs      - View security logs
  spectrectl scan      - Run manual security scan
  spectrectl config    - Edit configuration

Documentation: https://github.com/spectre-sec/spectre-linux

MOTD

    # Configure SSH (secure defaults)
    cat > "${ROOTFS}/etc/ssh/sshd_config" << 'SSHD'
Port 22
PermitRootLogin prohibit-password
PasswordAuthentication no
PubkeyAuthentication yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding no
PrintMotd yes
AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/ssh/sftp-server
SSHD

    # Enable services
    chroot "${ROOTFS}" /bin/sh -c "
        rc-update add networking boot
        rc-update add sshd default
        rc-update add audit default
    "

    # Create spectre user
    chroot "${ROOTFS}" /bin/sh -c "
        adduser -D -s /bin/bash -G wheel spectre
        echo 'spectre:spectre' | chpasswd
        echo '%wheel ALL=(ALL) ALL' >> /etc/sudoers
    "

    log "System configured"
}

# =============================================================================
# Step 6: Create initramfs
# =============================================================================
create_initramfs() {
    step "Creating initramfs"

    INITRAMFS_DIR="${BUILD_ROOT}/initramfs"
    ROOTFS="${BUILD_ROOT}/rootfs"

    mkdir -p "${INITRAMFS_DIR}"/{bin,sbin,etc,proc,sys,dev,newroot,usr/bin,usr/sbin}

    # Copy busybox
    cp "${ROOTFS}/bin/busybox" "${INITRAMFS_DIR}/bin/"
    chroot "${INITRAMFS_DIR}" /bin/busybox --install -s

    # Create init script
    cat > "${INITRAMFS_DIR}/init" << 'INIT'
#!/bin/sh

# Mount essential filesystems
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev

echo "Spectre Linux Bootloader"
echo "========================="

# Find and mount root filesystem
echo "Mounting root filesystem..."

# Try to find the root device
for device in /dev/sr0 /dev/sda1 /dev/vda1 /dev/nvme0n1p1; do
    if [ -b "$device" ]; then
        mount -o ro "$device" /newroot 2>/dev/null && break
    fi
done

# Check if squashfs exists
if [ -f /newroot/rootfs.squashfs ]; then
    mkdir -p /newroot/live
    mount -t squashfs /newroot/rootfs.squashfs /newroot/live
    mount -t overlay overlay -o lowerdir=/newroot/live,upperdir=/newroot/upper,workdir=/newroot/work /newroot/merged
    exec switch_root /newroot/merged /sbin/init
fi

# Direct boot
if [ -x /newroot/sbin/init ]; then
    exec switch_root /newroot /sbin/init
fi

echo "Failed to boot! Dropping to shell..."
exec /bin/sh
INIT
    chmod +x "${INITRAMFS_DIR}/init"

    # Create initramfs archive
    cd "${INITRAMFS_DIR}"
    find . | cpio -H newc -o | gzip > "${BUILD_ROOT}/initramfs.gz"

    log "Initramfs created"
}

# =============================================================================
# Step 7: Create ISO
# =============================================================================
create_iso() {
    step "Creating bootable ISO"

    ISO_DIR="${BUILD_ROOT}/iso"
    mkdir -p "${ISO_DIR}"/{boot/grub,EFI/BOOT,live}

    # Copy kernel and initramfs
    cp "${BUILD_ROOT}/vmlinuz" "${ISO_DIR}/boot/"
    cp "${BUILD_ROOT}/initramfs.gz" "${ISO_DIR}/boot/"

    # Create squashfs of rootfs
    log "Creating squashfs filesystem..."
    mksquashfs "${BUILD_ROOT}/rootfs" "${ISO_DIR}/live/rootfs.squashfs" -comp xz

    # Create GRUB config
    cat > "${ISO_DIR}/boot/grub/grub.cfg" << 'GRUB'
set timeout=5
set default=0

menuentry "Spectre Linux" {
    linux /boot/vmlinuz quiet
    initrd /boot/initramfs.gz
}

menuentry "Spectre Linux (Recovery Mode)" {
    linux /boot/vmlinuz single
    initrd /boot/initramfs.gz
}

menuentry "Spectre Linux (Debug)" {
    linux /boot/vmlinuz debug
    initrd /boot/initramfs.gz
}
GRUB

    # Create ISO
    log "Building ISO image..."
    grub-mkrescue -o "${PROJECT_ROOT}/iso/spectre-linux-${SPECTRE_VERSION}.iso" "${ISO_DIR}"

    log "ISO created: spectre-linux-${SPECTRE_VERSION}.iso"
}

# =============================================================================
# Main
# =============================================================================
main() {
    echo "=========================================="
    echo "  Spectre Linux Build System"
    echo "  Version: ${SPECTRE_VERSION}"
    echo "=========================================="

    prepare_build
    build_kernel
    create_rootfs
    install_spectre
    configure_system
    create_initramfs
    create_iso

    echo ""
    echo "=========================================="
    echo "  Build Complete!"
    echo "=========================================="
}

main "$@"
