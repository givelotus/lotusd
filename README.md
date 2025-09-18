<p align="center">
  <a href="https://lotusia.org">
    <img src="share/pixmaps/lotuslogo.png" alt="Lotus" title="Lotus" width="60%" style="max-width: 500px; height: auto;">
  </a>
</p>
 
<p align="center">
  <a href="https://github.com/LotusiaStewardship/lotusd">
    <img src="https://img.shields.io/badge/Main%20Fork-LotusiaStewardship-blue" alt="Main Fork: LotusiaStewardship">
  </a>
</p>
<p align="center">
  <a href="https://github.com/Boblepointu/lotusd/actions/workflows/lotus-main-ci.yml">
    <img src="https://github.com/Boblepointu/lotusd/actions/workflows/lotus-main-ci.yml/badge.svg?branch=master" alt="CI Status">
  </a>
  <a href="https://github.com/LotusiaStewardship/lotusd/releases/latest">
    <img src="https://img.shields.io/github/v/release/LotusiaStewardship/lotusd" alt="Latest Release">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/github/license/LotusiaStewardship/lotusd" alt="License">
  </a>
  <a href="https://github.com/LotusiaStewardship/lotusd/issues">
    <img src="https://img.shields.io/github/issues/LotusiaStewardship/lotusd" alt="Issues">
  </a>
  <a href="https://github.com/LotusiaStewardship/lotusd/network/members">
    <img src="https://img.shields.io/github/forks/LotusiaStewardship/lotusd" alt="Forks">
  </a>
  <a href="https://github.com/LotusiaStewardship/lotusd/stargazers">
    <img src="https://img.shields.io/github/stars/LotusiaStewardship/lotusd" alt="Stars">
  </a>
</p>

<p align="center">
  <a href="https://github.com/Boblepointu/lotusd">
    <img src="https://img.shields.io/badge/Development-Boblepointu-orange" alt="Development: Boblepointu">
  </a>
</p>

<p align="center">
  <a href="https://github.com/Boblepointu/lotusd/actions/workflows/lotus-main-ci.yml">
    <img src="https://github.com/Boblepointu/lotusd/actions/workflows/lotus-main-ci.yml/badge.svg?branch=master" alt="CI Status">
  </a>
  <a href="https://github.com/Boblepointu/lotusd/releases/latest">
    <img src="https://img.shields.io/github/v/release/Boblepointu/lotusd" alt="Latest Release">
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/github/license/Boblepointu/lotusd" alt="License">
  </a>
  <a href="https://github.com/Boblepointu/lotusd/issues">
    <img src="https://img.shields.io/github/issues/Boblepointu/lotusd" alt="Issues">
  </a>
  <a href="https://github.com/Boblepointu/lotusd/network/members">
    <img src="https://img.shields.io/github/forks/Boblepointu/lotusd" alt="Forks">
  </a>
  <a href="https://github.com/Boblepointu/lotusd/stargazers">
    <img src="https://img.shields.io/github/stars/Boblepointu/lotusd" alt="Stars">
  </a>
</p>

<div align="center">
  
  # 🌸Lotus: Digital Currency for Human Relationships🌸
  
  <hr>
  
  > *"Cultivating connections, growing prosperity, blooming together."*
  
</div>

## ✨ What is Lotus?

[Lotus](https://lotusia.org/) is a digital currency that enables instant payments to anyone, anywhere in the world. It uses peer-to-peer technology to operate with no central authority: managing transactions and issuing money are carried out collectively by the network. Lotus combines the best qualities of the modern monetary system and the new generation of digital cryptocurrencies, resulting in an ethical currency that is economically viable.

### 🌟 Key Features:
- **💯 Debt-free**: Issued through Proof-of-Work mining
- **📈 Inflationary**: No arbitrary issuance cap, removing incentives to hoard
- **🌊 Abundant**: Issuance of new Lotus is adjusted to demand of the Lotusia economy
- **📊 Stabilizing**: Lotus can be removed from circulation through voluntary destructive use to stabilize volatility

## 🧠 Core Principles

Reciprocity is the core of all human relationships. The Lotus currency facilitates and symbolizes the value we see in each other, allowing us to build a more connected and prosperous society.

## 🔧 Technology

Lotus is a fork of Bitcoin ABC that has been enhanced and modified to support the Lotusia vision. The blockchain is highly scalable, permissionless, and designed to adapt to the growing needs of the ecosystem.

## ⛏️ Mining Lotus

Lotus uses Proof-of-Work for issuance. You can participate in securing the network and earn newly minted Lotus through mining.

### 🖥️ GPU Mining

For optimal mining performance, we provide a dedicated GPU miner that utilizes OpenCL to efficiently mine Lotus blocks on your graphics card. Our GPU miner supports both solo mining and pool mining configurations.

#### 💎 Key Features:
- 🚀 OpenCL-based for high-performance mining
- 🔄 Compatible with both AMD and NVIDIA GPUs
- 🏊‍♂️ Supports both solo and pool mining
- ⚙️ Easy configuration through command line or config file

For detailed instructions on setting up and using the GPU miner, see the [GPU Mining Documentation](gpuminer/README.md).

## 🚀 Quick Start Examples

### 📦 Available Binary Packages

You can download the latest Lotus Root binaries from the [Releases page](https://github.com/LotusiaStewardship/lotusd/releases):

#### Package Options
- **Combined Packages**:
  - `lotus-binaries-[VERSION].tar.gz` - All Lotus binaries in a single tarball
  - `lotus-binaries-[VERSION].zip` - All Lotus binaries in a single zip file

- **Individual Component Packages**:
  - `lotus-gpu-miner-[VERSION].tar.gz` - GPU miner with required kernels (tar.gz format)
  - `lotus-gpu-miner-[VERSION].zip` - GPU miner with required kernels (zip format)
  - `lotus-node-[VERSION].tar.gz` - Lotus full node daemon (tar.gz format)
  - `lotus-node-[VERSION].zip` - Lotus full node daemon (zip format)
  - `lotus-qt-[VERSION].tar.gz` - Lotus desktop wallet (tar.gz format)
  - `lotus-qt-[VERSION].zip` - Lotus desktop wallet (zip format)
  - `lotus-cli-[VERSION].tar.gz` - Lotus command-line tools (tar.gz format)
  - `lotus-cli-[VERSION].zip` - Lotus command-line tools (zip format)

> **Note:** The GPU miner now includes embedded OpenCL kernel code, making it a completely self-contained binary.

For detailed GPU miner documentation, see the [GPU Mining Documentation](gpuminer/README.md).

#### 🏊‍♂️ Example: Mining on a Pool
##### Using the CLI Miner
```bash
# Replace with your own mining pool details and address
# Note: For pool mining, username and password can be any dummy values
lotus-miner-cli --rpc-password password --rpc-poll-interval 1 --rpc-url https://burnlotus.org --rpc-user miner --mine-to-address lotus_16PSJPZTD2aXDZJSkCYfdSC4jzkVzHk1JQGojw2BN --kernel-size 21 --poolmining
```

##### Using the Docker Miner
```bash
docker run --gpus all -it --rm ghcr.io/boblepointu/lotus-gpu-miner:latest --gpu-index 0 --kernel-size 22 --mine-to-address lotus_16PSJLkXR2zHXC4JCFmLcY6Tpxb9qLbP9rzcsGSgo --rpc-url https://burnlotus.org --poolmining
```

## 🌐 Community Resources

- 🏠 Website: [https://lotusia.org/](https://lotusia.org/)
- 🔍 Block Explorer: [https://explorer.lotusia.org/](https://explorer.lotusia.org/)
- 💬 Telegram Airdrop Channel: [https://t.me/LotusiaStewardship](https://t.me/LotusiaStewardship)
- 💬 Telegram Talk Channel: [https://t.me/LotusiaDiscourse](https://t.me/LotusiaDiscourse)
- 📚 Documentation: [https://docs.lotusia.org/](https://docs.lotusia.org/)
- 🌐 Pool: [https://burnlotus.org/](https://burnlotus.org/)

## 📜 License

Lotus is released under the terms of the MIT license. See [COPYING](COPYING) for more information or see <https://opensource.org/licenses/MIT>.

## 👨‍💻 Development Process

This Github repository contains the source code of Lotus. If you would like to contribute, please read [CONTRIBUTING](CONTRIBUTING.md).

## 🔐 Disclosure Policy

See [DISCLOSURE_POLICY](DISCLOSURE_POLICY.md)

---

<p align="center">
  <strong>🌸 Join us in creating a more connected and prosperous world! 🌸</strong>
</p>
