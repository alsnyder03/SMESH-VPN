# SMESH-VPN

A secure mesh VPN with Post-Quantum Cryptography.

## Features

- Post-quantum secure key exchange using hybrid classical/post-quantum cryptography
- End-to-end encrypted communication between nodes
- Mesh topology allowing direct peer-to-peer connections
- Certificate-based identity system for secure authentication
- Protection against MITM attacks during key exchange
- Automatic peer discovery through a central discovery server

## Requirements

- Python 3.8+
- pytun/tunctl or equivalent (for TUN interface support)

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/SMESH-VPN.git
cd SMESH-VPN
```

2. Install dependencies:

```bash
pip install -r requirements.txt
```

## Certificate Setup

SMESH-VPN uses certificate-based authentication to ensure that only authorized clients can connect to the network and to protect against MITM attacks.

### Create a Certificate Authority (CA)

Before clients can connect, you need to set up a Certificate Authority:

```bash
python ca_manager.py --create-ca --ca-dir ca
```

### Issue Client Certificates

Issue certificates for each client that needs to connect:

```bash
python ca_manager.py --issue-cert --ca-dir ca --common-name "Client1"
```

This will generate a client certificate in the `ca/clients/<client_id>` directory.

### List Authorized Clients

To view all authorized clients:

```bash
python ca_manager.py --list-clients --ca-dir ca
```

### Revoke Client Certificates

To revoke a certificate:

```bash
python ca_manager.py --revoke-cert --ca-dir ca --client-id <client_id>
```

## Running the Discovery Server

Start the discovery server:

```bash
sudo python server/discovery_server.py
```

## Running a Client

Start a VPN client with certificate authentication:

```bash
sudo python client/client.py --cert-dir ca/clients/<client_id> --client-id <client_id>
```

Or specify additional parameters:

```bash
sudo python client/client.py -i 10.10.0.2 -p 9000 -d discovery.example.com:8000 --cert-dir ca/clients/<client_id> --client-id <client_id>
```

## Security Considerations

- The certificates are used to authenticate clients during connection establishment
- All key exchanges are protected against MITM attacks
- Only authorized clients with valid certificates can connect to the VPN
- The discovery server validates client certificates before allowing connections
- All data exchanged between peers is end-to-end encrypted

## Docker Support

You can also run the VPN components in Docker:

```bash
docker-compose up -d
```

## Testing

Run the tests:

```bash
python -m unittest discover tests
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
