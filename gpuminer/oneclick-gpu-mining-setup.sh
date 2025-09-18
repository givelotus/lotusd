#!/usr/bin/env bash

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() { echo -e "${GREEN}[$(date +'%H:%M:%S')] $*${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $*${NC}"; }
err() { echo -e "${RED}[ERROR] $*${NC}"; }
info() { echo -e "${BLUE}[INFO] $*${NC}"; }

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  err "Run as root: sudo bash $0"
  exit 1
fi

ACTUAL_USER=${SUDO_USER:-$(logname 2>/dev/null || echo "")}
[[ -z "$ACTUAL_USER" ]] && { err "Could not determine invoking user"; exit 1; }
ACTUAL_HOME=$(getent passwd "$ACTUAL_USER" | cut -d: -f6)

PROJECT_DIR="$ACTUAL_HOME/lotus-gpu-miner"
mkdir -p "$PROJECT_DIR/logs"

log "Updating system and installing prerequisites"
apt-get update -y
apt-get install -y curl wget gnupg ca-certificates lsb-release software-properties-common build-essential dkms git unzip htop clinfo

log "Installing Docker engine"
install -d -m 0755 /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
usermod -aG docker "$ACTUAL_USER"
systemctl enable --now docker

log "Detecting GPU vendor"
VENDOR="unknown"
if lspci | grep -i -q 'NVIDIA'; then
  VENDOR="nvidia"
elif lspci | grep -i -q 'AMD\|Advanced Micro Devices'; then
  VENDOR="amd"
fi
log "Detected: $VENDOR"

case "$VENDOR" in
  nvidia)
    log "Installing NVIDIA drivers and container toolkit"
    ubuntu-drivers autoinstall || warn "ubuntu-drivers failed; ensure NVIDIA driver installed"
    distribution=$(. /etc/os-release;echo $ID$VERSION_ID)
    curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit.gpg
    curl -fsSL https://nvidia.github.io/libnvidia-container/$distribution/libnvidia-container.list | \
      sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit.gpg] https://#g' > /etc/apt/sources.list.d/nvidia-container-toolkit.list
    apt-get update -y
    apt-get install -y nvidia-driver-535 nvidia-container-toolkit
    nvidia-ctk runtime configure --runtime=docker || true
    systemctl restart docker
    ;;
  amd)
    log "Installing AMD OpenCL (Mesa) and enabling device nodes"
    apt-get install -y mesa-opencl-icd ocl-icd-libopencl1 mesa-vulkan-drivers xserver-xorg-video-amdgpu libdrm-amdgpu1
    echo "options amdgpu kfd=1 compute=1" > /etc/modprobe.d/amdgpu.conf
    echo "amdgpu" >> /etc/modules
    cat > /etc/udev/rules.d/70-amdgpu.rules <<'EOF'
SUBSYSTEM=="drm", KERNEL=="renderD*", GROUP="render", MODE="0666"
SUBSYSTEM=="drm", KERNEL=="card*", GROUP="video", MODE="0666"
SUBSYSTEM=="kfd", KERNEL=="kfd", GROUP="render", MODE="0666"
KERNEL=="kfd", MODE="0666"
KERNEL=="renderD*", MODE="0666"
EOF
    groupadd -f render; groupadd -f video
    usermod -aG video,render "$ACTUAL_USER"
    update-initramfs -u || true
    modprobe amdgpu kfd=1 || true
    [ -e /dev/kfd ] || mknod /dev/kfd c 511 0 || true
    chmod 666 /dev/kfd /dev/dri/* 2>/dev/null || true
    udevadm control --reload-rules && udevadm trigger || true
    ;;
  *)
    warn "No supported GPU detected. Proceeding; Docker run may fail."
    ;;
esac

log "Pulling GPU miner images"
docker pull ghcr.io/boblepointu/lotus-gpu-miner:latest || true
docker pull ghcr.io/boblepointu/lotus-gpu-miner:amd-latest || true

log "Creating docker-compose.yml"
COMPOSE="$PROJECT_DIR/docker-compose.yml"
if [[ "$VENDOR" == "nvidia" ]]; then
  cat > "$COMPOSE" <<'YAML'
services:
  lotus-miner:
    image: ghcr.io/boblepointu/lotus-gpu-miner:latest
    container_name: lotus-miner-gpu
    environment:
      - MINER_ADDRESS=
      - KERNEL_SIZE=22
      - RPC_URL=https://burnlotus.org
      - RPC_USER=miner
      - RPC_PASSWORD=password
      - RPC_POLL_INTERVAL=1
      - INSTANCES_PER_GPU=4
      - POOL_MINING=true
    deploy:
      resources:
        limits:
          memory: 16G
    volumes:
      - ./logs:/var/log/lotus
    runtime: nvidia
    deploy: { }
    restart: unless-stopped
YAML
else
  cat > "$COMPOSE" <<'YAML'
services:
  lotus-miner:
    image: ghcr.io/boblepointu/lotus-gpu-miner:amd-latest
    container_name: lotus-miner-gpu
    devices:
      - /dev/kfd:/dev/kfd
      - /dev/dri:/dev/dri
    group_add:
      - video
      - render
    environment:
      - MINER_ADDRESS=
      - KERNEL_SIZE=22
      - RPC_URL=https://burnlotus.org
      - RPC_USER=miner
      - RPC_PASSWORD=password
      - RPC_POLL_INTERVAL=1
      - INSTANCES_PER_GPU=4
      - POOL_MINING=true
      - OPENCL_VENDOR_PATH=/etc/OpenCL/vendors
      - HSA_OVERRIDE_GFX_VERSION=8.0.3
    deploy:
      resources:
        limits:
          memory: 16G
    volumes:
      - ./logs:/var/log/lotus
    restart: unless-stopped
YAML
fi

log "Creating helper scripts"
cat > "$PROJECT_DIR/start-mining.sh" <<'SH'
#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
if ! command -v docker compose >/dev/null 2>&1; then
  echo "docker compose plugin missing"; exit 1
fi
if [[ -z "${MINER_ADDRESS:-}" ]]; then
  if ! grep -q '^\s*- MINER_ADDRESS=' docker-compose.yml; then
    echo "Set MINER_ADDRESS env via: MINER_ADDRESS=lotus_... ./start-mining.sh"; exit 1
  fi
fi
MINER_ADDRESS="${MINER_ADDRESS:-}" docker compose up -d
echo "Started. Logs: docker compose logs -f"
SH

cat > "$PROJECT_DIR/stop-mining.sh" <<'SH'
#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
docker compose down || true
SH

chmod +x "$PROJECT_DIR"/*.sh
chown -R "$ACTUAL_USER:$ACTUAL_USER" "$PROJECT_DIR"

echo ""
echo "=============================================="
echo "Lotus GPU miner setup complete for: $VENDOR"
echo "Project dir: $PROJECT_DIR"
echo "Usage:"
echo "  MINER_ADDRESS=lotus_xxx $PROJECT_DIR/start-mining.sh"
echo "  $PROJECT_DIR/stop-mining.sh"
echo "Logs: docker compose -f $PROJECT_DIR/docker-compose.yml logs -f"
echo "If AMD, reboot may be required for /dev/kfd permissions."
echo "=============================================="


