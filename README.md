# CWE (Compatible with everything)

A lightweight, asynchronous, multi-protocol file manager written in Python. Designed to interface with local file systems, remote network shares, cloud storage providers, and distributed networks.

---

## Features

- **Multi-Protocol Abstraction Engine**: Structured support for 25+ protocols spanning local disks, SAN/NAS shares, object storage, and P2P networks.
- **Smart Sorting**: Column-based sorting with accurate numerical byte comparison for file sizes.
- **Zero Heavy Dependencies**: Runs out of the box using Python's standard library.

---

## Architecture Overview


```

```
                      ┌───────────────────────────┐
                      │            CWE            │
                      └─────────────┬─────────────┘
                                    │
                     ┌──────────────┴──────────────┐
                     │   ProtocolManager Engine    │
                     └──────────────┬──────────────┘
                                    │
   ┌──────────────────┬─────────────┼─────────────┬──────────────────┐
   │                  │             │             │                  │

```

┌──────┴──────┐    ┌──────┴──────┐┌─────┴─────┐┌──────┴──────┐    ┌──────┴──────┐
│ Direct Disk │    │ Network     ││ Cloud/S3  ││ Transfer    │    │ P2P / Web3  │
│ (Local/NVMe)│    │ (SMB/NFS)   ││(AWS/Azure)││(SFTP/FTP)   │    │(IPFS/Sync)  │
└─────────────┘    └─────────────┘└───────────┘└─────────────┘    └─────────────┘

```

---

## Supported Protocols

| Category | Protocols / Drivers |
| :--- | :--- |
| **Local & Storage** | Direct OS Access, MTP, PTP, UASP/UMS, NVMe-oF, Fibre Channel |
| **Network Shares** | SMB (1/2/3), NFS, AFP, WebDAV, iSCSI |
| **File Transfer** | FTP, FTPS, SFTP, SCP, HTTP/S, HTTP/3, Rsync |
| **Cloud & Object** | S3 (AWS/MinIO), OpenStack Swift, Google Cloud Storage, Azure Blob |
| **P2P & Distributed**| IPFS, BitTorrent, Syncthing |
| **Cluster & HPC** | CephFS, GlusterFS, HDFS, 9P |

---

## Prerequisites

- **Python 3.8+**
- **Tkinter**: Included in standard Python installers for Windows/macOS.

On Linux (Debian/Ubuntu), install Tkinter explicitly if it is missing:

```bash
sudo apt-get update
sudo apt-get install python3-tk

```

---

## Installation

1. **Clone the repository**:
```bash
git clone https://github.com/Miaoumap24/CWE.git
cd CWE

```


2. *(Optional)* **Set up a virtual environment**:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

```


3. **Install optional driver dependencies**:
```bash
pip install -r requirements.txt

```



---

## Usage

Start the file explorer with:

```bash
python CWE.py

```

### Key Navigation

* **Dropdown Selectors**: Filter endpoints by category and choose your desired protocol.
* **Connect / Mount**: Open the protocol setup modal to specify hosts, credentials, and access paths.
* **Path Bar**: Type any valid target path and press `Enter` (or click `Go`) to load.
* **Double-Click**: Open folders directly from the primary grid view.

---

## System Requirements & External Backends

While the base GUI operates natively using Python, integrating live remote backends requires external tools installed on your host system path:

* **Rclone**: Required for S3, WebDAV, SFTP, and Cloud Object backends (`rclone` executable on `$PATH`).
* **OpenSSH/Paramiko**: Required for direct SSH/SFTP terminal hooks.
* **Samba / cifs-utils**: Required for mounting remote SMB shares on Linux hosts.

---

## Project Structure

```
.
├── CWE.py               # Main App
├── requirements.txt     # Optional Python dependencies for backend bindings
└── README.md            # Project documentation

```

---

## License

Distributed under the **AGPL-3.0**. See `LICENSE` for details.
