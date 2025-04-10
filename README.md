# SMESH-VPN

A mesh-based Virtual Private Network system where each node can communicate directly with other nodes in the network without relying on a central server for routing traffic.

## Features

- Fully decentralized mesh network topology
- Encrypted peer-to-peer connections
- Automatic peer discovery
- NAT traversal capabilities
- Cross-platform support (Linux, Windows, macOS)

## Components

### Client

The client establishes encrypted tunnels to other peers in the mesh network, handles routing, and manages the virtual network interface.

### Discovery Server

The discovery server helps peers find each other on the network. It acts only as a facilitator for initial connection and doesn't route any VPN traffic.

## Installation

Venv must exist

```bash
python -m venv .venv
```

```bash
./.venv/Scripts/activate.ps1
```

or equivalent for other operating system

```bash
# Clone the repository
git clone https://github.com/yourusername/SMESH-VPN.git
cd SMESH-VPN

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Running the Discovery Server

```bash
python server/discovery_server.py
```

### Running the Client

```bash
python client/client.py
```

The client will create a virtual network interface and establish connections with other peers in the mesh.

## Configuration

Create a JSON configuration file at `~/.mesh_vpn/config.json`:

```json
{
  "listen_port": 9000,
  "discovery_servers": ["mesh-discovery.example.com:8000"],
  "interface": "tun0",
  "subnet": "10.10.0.0/24",
  "local_ip": "10.10.0.1"
}
```

## Security Considerations

- All traffic between peers is encrypted
- Peers authenticate each other using public key cryptography
- The system doesn't rely on a central point for traffic routing, increasing privacy

## License

MIT License
