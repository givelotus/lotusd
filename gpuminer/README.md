<p align="center">
  <h1>🌸 Lotus GPU Miner 🌸</h1>
</p>

<p align="center">
  <a href="https://github.com/Boblepointu/lotusd/actions/workflows/lotus-main-ci.yml">
    <img src="https://github.com/Boblepointu/lotusd/actions/workflows/lotus-main-ci.yml/badge.svg?branch=master" alt="CI Status">
  </a>
  <a href="https://github.com/LotusiaStewardship/lotusd/releases/latest">
    <img src="https://img.shields.io/github/v/release/LotusiaStewardship/lotusd" alt="Latest Release">
  </a>
  <a href="../LICENSE">
    <img src="https://img.shields.io/github/license/LotusiaStewardship/lotusd" alt="License">
  </a>
  <a href="https://opencl.org">
    <img src="https://img.shields.io/badge/OpenCL-Compatible-brightgreen" alt="OpenCL Compatible">
  </a>
</p>

<div align="center">
  
  > *"Harness the power of your GPU for optimal Lotus mining"*
  
  <hr>
  
  **[📦 Download](#-using-pre-built-binaries)** • **[🐳 Docker Images](#docker-images)** • **[🚀 Quick Start](#-quick-start-examples)** • **[📚 Documentation](#-advanced-architecture)**
</div>

The Lotus GPU miner enables high-performance mining for the Lotus network, using OpenCL to harness the power of your GPU for optimal mining efficiency.

## ✨ Features

- **Zero-Stall Mining Architecture**: Maximizes GPU utilization with continuous mining cycles
- **Intelligent Header Management**: Avoids redundant work through smart block header comparison
- **Stabilized Hashrate Metrics**: 60-second moving average with 15-second warm-up period
- **Asynchronous Share Submission**: Continues mining while shares are being submitted
- **Intelligent Nonce Management**: Prevents exhaustion by automatically resetting nonce indexes
- **Embedded OpenCL Kernels**: Multiple kernel implementations included to optimize for different GPUs
- **OpenCL-based Mining**: Works with a wide variety of GPUs from NVIDIA, AMD, and Intel
- **Pool and Solo Mining**: Support for both mining modes with seamless transitions

## 🏊‍♂️ Mining Modes

### 🌊 Pool Mining

Pool mining mode submits shares to a mining pool, allowing you to receive more frequent but smaller rewards. Enable this mode with the `--poolmining` flag:

```bash
./lotus-miner-cli --poolmining -a https://burnlotus.org -o YOUR_LOTUS_ADDRESS
```

### 🔒 Solo Mining

Solo mining connects directly to a Lotus node, granting you the full block reward when you find a block. This mode is used when the `--poolmining` flag is not present:

```bash
./lotus-miner-cli -a http://127.0.0.1:10604 -u username -p password -o YOUR_LOTUS_ADDRESS
```

## 🚀 Quick Start Examples

### 📦 Using Pre-built Binaries

You can download the latest Lotus GPU Miner binaries from the [GitHub Releases page](https://github.com/LotusiaStewardship/lotusd/releases/latest):

#### Available Package Options

##### Combined Packages (All Lotus Components)
- **Tar Archive**: `lotus-binaries-[VERSION].tar.gz` - Contains all Lotus binaries including node, wallet, and GPU miner
- **Zip Archive**: `lotus-binaries-[VERSION].zip` - Same contents as the tar.gz but in zip format

##### GPU Miner Specific Packages
- **Tar Archive**: `lotus-gpu-miner-[VERSION].tar.gz` - Contains only the GPU miner with required OpenCL kernels
- **Zip Archive**: `lotus-gpu-miner-[VERSION].zip` - Same as above but in zip format

#### Installation Instructions

##### Using the GPU Miner Package

```bash
# For tar.gz format
wget https://github.com/LotusiaStewardship/lotusd/releases/download/v0.4.0/lotus-gpu-miner-0.4.0.tar.gz
tar -xzf lotus-gpu-miner-0.4.0.tar.gz -C .
cd gpu-miner-dir
chmod +x lotus-miner-cli
./lotus-miner-cli -g 0 -s 25 -o YOUR_LOTUS_ADDRESS -i 1 -a https://burnlotus.org -m

# You can also use the symlink if you prefer:
# ./lotus-gpu-miner -g 0 -s 25 -o YOUR_LOTUS_ADDRESS -i 1 -a https://burnlotus.org -m

# For zip format
wget https://github.com/LotusiaStewardship/lotusd/releases/download/v0.4.0/lotus-gpu-miner-0.4.0.zip
unzip lotus-gpu-miner-0.4.0.zip -d gpu-miner-dir
cd gpu-miner-dir
chmod +x lotus-miner-cli
./lotus-miner-cli -g 0 -s 25 -o YOUR_LOTUS_ADDRESS -i 1 -a https://burnlotus.org -m
```

##### Extracting from the Combined Package

```bash
# For tar.gz format
wget https://github.com/LotusiaStewardship/lotusd/releases/download/v0.4.0/lotus-binaries-0.4.0.tar.gz
tar -xzf lotus-binaries-0.4.0.tar.gz
cd gpu-miner-package
chmod +x lotus-miner-cli
./lotus-miner-cli -g 0 -s 25 -o YOUR_LOTUS_ADDRESS -i 1 -a https://burnlotus.org -m

# For zip format
wget https://github.com/LotusiaStewardship/lotusd/releases/download/v0.4.0/lotus-binaries-0.4.0.zip
unzip lotus-binaries-0.4.0.zip -d gpu-miner-package
cd gpu-miner-package
chmod +x lotus-miner-cli
./lotus-miner-cli -g 0 -s 25 -o YOUR_LOTUS_ADDRESS -i 1 -a https://burnlotus.org -m
```

> **ℹ️ Note**: The OpenCL kernel code is now embedded directly in the binary, eliminating the need for the external `kernels` directory. This provides a cleaner, more reliable distribution and a fully self-contained binary.

#### 🏊‍♂️ Example: Mining on a Pool

```bash
# Replace with your own address
lotus-miner-cli -g 0 -s 27 -o lotus_16PSJNgWFFf14otE17Fp43HhjbkFchk4Xgvwy2X27 -i 1 -a https://burnlotus.org -m
```

#### 🔒 Example: Solo Mining

```bash
lotus-miner-cli -g 0 -s 25 -o YOUR_LOTUS_ADDRESS -i 3 -a http://127.0.0.1:10604 -u your_username -p your_password
```

### 🔍 Command Line Parameters

```
USAGE:
    lotus-miner-cli [FLAGS] [OPTIONS]

FLAGS:
    -h, --help          Prints help information
    -m, --poolmining    Enable pool mining mode
    -d, --debug         Enable debug logging
    -V, --version       Prints version information

OPTIONS:
    -g, --gpu-index <gpu_index>                    GPU index to use (default: 0)
    -s, --kernel-size <kernel_size>                Kernel size parameter (default: 23)
    -o, --mine-to-address <mine_to_address>        Coinbase Output Address
    -p, --rpc-password <rpc_password>              Lotus RPC password
    -i, --rpc-poll-interval <rpc_poll_interval>    Block template polling interval (seconds)
    -a, --rpc-url <rpc_url>                        Lotus RPC address
    -u, --rpc-user <rpc_user>                      Lotus RPC username
```

## 🔬 Advanced Architecture

### ⚡ Zero-Stall Mining Architecture

The Lotus GPU Miner implements a sophisticated zero-stall mining architecture designed to maximize GPU efficiency:

1. **Strategic Work Prefetching**: A dedicated background thread consistently fetches new work before it's needed, ensuring no GPU stalls occur while waiting for the next job.

2. **Smart Header Management**: Intelligent block header comparison avoids redundant mining operations:
   - New headers are compared against current ones to prevent mining the same block twice
   - Identical headers are detected, allowing the miner to continue on the current work with reset nonces
   - Provides detailed logging of header transitions for better debugging

3. **Asynchronous Share Submission**: When a valid share is found:
   - The share is submitted in the background
   - Mining continues immediately with the next block
   - The GPU experiences zero downtime during share submission

4. **Continuous Mining Loop**: The zero-wait mining cycle creates a continuous flow of work for the GPU:
   ```
   ┌─────────────────┐    ┌────────────────┐    ┌────────────────┐
   │ Prefetch Work   │───▶│ Process Mining │───▶│ Submit Results │
   └─────────────────┘    └────────────────┘    └────────────────┘
           ▲                                            │
           └────────────────────────────────────────────┘
   ```

5. **Nonce Exhaustion Prevention**: Automatic nonce index resets prevent the "Exhaustively searched nonces" error, ensuring continuous mining.

### 📊 Stabilized Hashrate Reporting

The miner implements an intelligent hashrate calculation system:

- **60-Second Moving Average**: Hashrate is calculated over a 60-second window for stable readings
- **15-Second Warm-Up Period**: Initial hashrate estimates are stabilized to prevent unrealistically high readings
- **Intelligent Blending**: Gradually transitions from conservative estimates to measured values during warm-up
- **Self-Adjusting Algorithm**: Adapts to different hardware performance characteristics
- **Debug Logging**: Logs show the stabilization process when using the `--debug` flag

## 🐳 Docker Support

### Docker Images

The official Lotus GPU Miner images are available on GitHub Container Registry:

- **NVIDIA Latest**: `ghcr.io/boblepointu/lotus-gpu-miner:latest`
- **AMD Latest**: `ghcr.io/boblepointu/lotus-gpu-miner:amd-latest`
- **Versioned (NVIDIA)**: `ghcr.io/boblepointu/lotus-gpu-miner:v0.4.0` (replace with specific version)
- **Versioned (AMD)**: `ghcr.io/boblepointu/lotus-gpu-miner:amd-v0.4.0`

You can view all available tags at [GitHub Container Registry](https://github.com/Boblepointu/lotusd/pkgs/container/lotus-gpu-miner).

### Docker Usage Examples

The easiest way to use the Lotus GPU miner is through Docker. This ensures you have all the necessary dependencies without having to install them on your host system.

## 🚀 One-Click Setup (Ubuntu 24.04)

```bash
curl -fsSL https://raw.githubusercontent.com/LotusiaStewardship/lotusd/master/gpuminer/oneclick-gpu-mining-setup.sh | sudo bash

# After installation (may require reboot on AMD):
MINER_ADDRESS=lotus_16PSJLkXR2zHXC4JCFmLcY6Tpxb9qLbP9rzcsGSgo $HOME/lotus-gpu-miner/start-mining.sh
```

The script detects your GPU vendor (NVIDIA or AMD), installs Docker and required runtime components, pulls the appropriate miner image, and generates a `docker-compose.yml` in `$HOME/lotus-gpu-miner`.

## Building the Docker Image

```bash
# Build from the root directory of the repository
docker build -t lotus-gpu-miner -f dockerfiles/Dockerfile.lotus-gpu-miner .
```

#### Basic Usage
```bash
# Using a Lotus address - both short and long-form arguments work
docker run --gpus all -it --rm ghcr.io/boblepointu/lotus-gpu-miner:latest lotus_16PSJLkXR2zHXC4JCFmLcY6Tpxb9qLbP9rzcsGSgo

# With short-form arguments
docker run --gpus all -it --rm ghcr.io/boblepointu/lotus-gpu-miner:latest -g 0 -s 22 -o lotus_16PSJLkXR2zHXC4JCFmLcY6Tpxb9qLbP9rzcsGSgo -a https://burnlotus.org -m

# With long-form arguments
docker run --gpus all -it --rm ghcr.io/boblepointu/lotus-gpu-miner:latest --gpu-index 0 --kernel-size 22 --mine-to-address lotus_16PSJLkXR2zHXC4JCFmLcY6Tpxb9qLbP9rzcsGSgo --rpc-url https://burnlotus.org --poolmining
```

#### Using Environment Variables (Recommended Method)
```bash
docker run --gpus all -it --rm \
  -e MINER_ADDRESS="lotus_16PSJLkXR2zHXC4JCFmLcY6Tpxb9qLbP9rzcsGSgo" \
  -e GPU_INDEX=0 \
  -e KERNEL_SIZE=22 \
  -e RPC_URL="https://burnlotus.org" \
  -e POOL_MINING=true \
  -e INSTANCES_PER_GPU=4 \
  ghcr.io/boblepointu/lotus-gpu-miner:latest
```

#### Advanced Usage
```bash
# Custom RPC settings
docker run --gpus all -it --rm \
  -e MINER_ADDRESS="lotus_16PSJLkXR2zHXC4JCFmLcY6Tpxb9qLbP9rzcsGSgo" \
  -e RPC_URL="http://your-lotus-node:9052" \
  -e RPC_USER="your-username" \
  -e RPC_PASSWORD="your-password" \
  -e RPC_POLL_INTERVAL=2 \
  ghcr.io/boblepointu/lotus-gpu-miner:8.3.47
```

### Docker Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MINER_ADDRESS` | Lotus address to mine to | Random from built-in list |
| `GPU_INDEX` | GPU index to use | 0 |
| `KERNEL_SIZE` | Kernel size (20-22) | 22 |
| `RPC_URL` | RPC server URL | https://burnlotus.org |
| `RPC_USER` | RPC username | miner |
| `RPC_PASSWORD` | RPC password | password |
| `RPC_POLL_INTERVAL` | RPC polling interval in seconds | 1 |
| `POOL_MINING` | Enable pool mining | true |
| `INSTANCES_PER_GPU` | Mining instances per GPU | 4 |

The Docker container will automatically spawn mining instances for each detected NVIDIA GPU, running multiple instances per GPU to maximize hash rate.

## 🔧 Performance Tuning

### Kernel Size (`-s, --kernel-size`)

The kernel size parameter controls how many nonces are processed in a single GPU kernel invocation. This directly impacts your hashrate:

- Higher values = more hashes per second, but potentially higher GPU load
- Lower values = less GPU load, but fewer hashes per second
- Recommended ranges:
  - Entry-level GPUs: 21-24
  - Mid-range GPUs: 24-27
  - High-end GPUs: 26-30

### Poll Interval (`-i, --rpc-poll-interval`)

This parameter controls how frequently the miner requests new work from the server:

- Lower values (1-2 seconds): More aggressive polling, better for pools with rapidly changing work
- Higher values (3-5 seconds): Less network traffic, suitable for solo mining or stable pools

## 🛠️ Build & Run from Source

### 🐧 Linux

```bash
# Install dependencies
sudo apt update
sudo apt install -y ocl-icd-libopencl1 ocl-icd-opencl-dev clinfo build-essential pkg-config curl

# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone repository
git clone https://github.com/Boblepointu/lotusd.git
cd lotusd/gpuminer

# Build
cargo build --release

# Run
./target/release/lotus-miner-cli -g 0 -s 27 -o YOUR_LOTUS_ADDRESS -i 1 -a https://burnlotus.org -m
```

### 🪟 Windows

1. Install [Rust](https://static.rust-lang.org/rustup/dist/x86_64-pc-windows-msvc/rustup-init.exe)
2. Install OpenCL for your GPU: [AMD](https://github.com/GPUOpen-LibrariesAndSDKs/OCL-SDK/releases) or [NVIDIA](https://developer.nvidia.com/cuda-downloads)
3. Clone and build:
   ```
   git clone https://github.com/Boblepointu/lotusd.git
   cd lotusd\gpuminer
   cargo build --release
   ```
4. Run with:
   ```
   .\target\release\lotus-miner-cli -g 0 -s 27 -o YOUR_LOTUS_ADDRESS -i 1 -a https://burnlotus.org -m
   ```

### 🍎 MacOS

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env

# Clone and build
git clone https://github.com/Boblepointu/lotusd.git
cd lotusd/gpuminer
cargo build --release

# Run
./target/release/lotus-miner-cli -g 0 -s 25 -o YOUR_LOTUS_ADDRESS -i 1 -a https://burnlotus.org -m
```

## 🔍 Troubleshooting

### Common Issues

1. **"Error: Exhaustively searched nonces"**
   - This should be fixed by the nonce index reset feature
   - If you still encounter it, try a larger kernel size with `-s 27` or `-s 28`

2. **OpenCL Initialization Errors**
   - Ensure your OpenCL drivers are properly installed
   - Verify GPU compatibility with `clinfo`
   - Try different GPU with `-g 1` if multiple GPUs are available

3. **Unstable Hashrate**
   - The 60-second moving average with 15-second warm-up should stabilize readings
   - Initial high values will normalize within 15 seconds of starting

4. **Connection Issues**
   - Verify your network connection to the pool/node
   - Check if the RPC URL is correct
   - For solo mining, ensure your node is fully synchronized

### Debugging

Enable debug output with `--debug` to see detailed information about:
- RPC communication with the server
- Block header transitions
- Share submission process
- Hashrate stabilization metrics
- Nonce management

## 💻 Development & Contribution

The Lotus GPU Miner is open source and welcomes contributions. Key components:

- **lib.rs**: Core mining logic and Zero-Stall Architecture
- **miner.rs**: OpenCL kernel management and GPU interfacing
- **block.rs**: Block structure and manipulation
- **sha256.rs**: Lotus-specific hash implementation
- **lotus_og.cl**: OpenCL mining kernel
- **main.rs**: CLI interface and program entry point

## ⚙️ Kernel Options

The Lotus GPU Miner includes two different OpenCL kernel implementations that you can choose from based on your hardware and mining preferences:

### 🌸 Lotus Original Kernel (Default)

```bash
lotus-miner-cli --kernel-type lotus_og [other parameters]
```

This is the default kernel optimized specifically for Lotus mining. It typically offers the best performance and is recommended for most users.

### 🧮 POCLBM Kernel

```bash
lotus-miner-cli --kernel-type poclbm [other parameters]
```

This alternative kernel is based on the POCLBM project (PyOpenCL Bitcoin Miner). It may offer better performance on some older or specific GPU architectures.

### 🔍 Choosing the Right Kernel

- **For newer GPUs**: Start with the default `lotus_og` kernel as it's optimized for modern architectures
- **For older GPUs**: Try the `poclbm` kernel which might work better with legacy hardware
- **For maximum efficiency**: Test both kernels and monitor your hashrate to see which one performs better on your specific hardware

Both kernels are embedded directly in the binary, so no external files are needed regardless of which one you choose.

---

<p align="center">
  <strong>🌸 Happy Mining! 🌸</strong><br>
  <em>Authors: Alexandre Guillioud (FrenchBTC) & Tobias Ruck</em>
</p>