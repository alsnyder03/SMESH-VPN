#!/usr/bin/env python3
"""
Certificate Authority Management Tool for SMESH-VPN

This script provides an easy way to manage the Certificate Authority (CA) for SMESH-VPN,
including creating client certificates, listing authorized clients, and revoking certificates.
"""

import argparse
import os
import sys
import uuid
import logging
from pathlib import Path
from common.certificates import CertificateAuthority

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("ca_manager")


def main():
    parser = argparse.ArgumentParser(
        description="SMESH-VPN Certificate Authority Manager"
    )

    # Main action arguments
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument(
        "--create-ca", action="store_true", help="Create a new Certificate Authority"
    )
    action_group.add_argument(
        "--issue-cert", action="store_true", help="Issue a new client certificate"
    )
    action_group.add_argument(
        "--revoke-cert", action="store_true", help="Revoke a client certificate"
    )
    action_group.add_argument(
        "--list-clients", action="store_true", help="List all authorized clients"
    )

    # CA directory
    parser.add_argument(
        "--ca-dir", type=str, default="ca", help="Directory for CA files (default: ca)"
    )

    # Arguments for issuing certificates
    parser.add_argument(
        "--client-id",
        type=str,
        help="Client ID for the certificate (generates UUID if not provided)",
    )
    parser.add_argument(
        "--common-name",
        type=str,
        help="Common name for the certificate (required when issuing)",
    )
    parser.add_argument(
        "--valid-days",
        type=int,
        default=365,
        help="Number of days the certificate will be valid (default: 365)",
    )

    args = parser.parse_args()

    try:
        # Handle creating a new CA
        if args.create_ca:
            ca_path = Path(args.ca_dir)
            if ca_path.exists() and (ca_path / "ca_cert.pem").exists():
                print(
                    f"CA already exists in {args.ca_dir}. Use --force to overwrite (not implemented yet)."
                )
                return 1

            print(f"Creating new Certificate Authority in {args.ca_dir}...")
            ca = CertificateAuthority(ca_dir=args.ca_dir, create_if_missing=True)
            print(f"Certificate Authority created successfully in {args.ca_dir}")
            return 0

        # For other actions, load the existing CA
        try:
            ca = CertificateAuthority(ca_dir=args.ca_dir, create_if_missing=False)
        except FileNotFoundError:
            print(
                f"No Certificate Authority found in {args.ca_dir}. Use --create-ca to create one."
            )
            return 1

        # Handle issuing a certificate
        if args.issue_cert:
            if not args.common_name:
                print("Error: --common-name is required when issuing a certificate.")
                return 1

            client_id = args.client_id or str(uuid.uuid4())
            print(f"Issuing certificate for {args.common_name} (ID: {client_id})...")

            # Create client cert directory
            cert_dir = os.path.join(args.ca_dir, "clients")
            os.makedirs(cert_dir, exist_ok=True)
            client_dir = os.path.join(cert_dir, client_id)
            os.makedirs(client_dir, exist_ok=True)

            # Issue the certificate
            key_pem, cert_pem = ca.issue_client_certificate(
                client_id, args.common_name, args.valid_days
            )

            # Save the certificate files
            with open(os.path.join(client_dir, "client_cert.pem"), "wb") as f:
                f.write(cert_pem)

            with open(os.path.join(client_dir, "client_key.pem"), "wb") as f:
                f.write(key_pem)

            # Also save the CA certificate
            with open(os.path.join(client_dir, "ca_cert.pem"), "wb") as f:
                f.write(ca.get_ca_certificate_pem())

            print(
                f"Certificate issued successfully for {args.common_name} (ID: {client_id})"
            )
            print(f"Certificate files saved in: {client_dir}")
            print("\nTo connect with this certificate, run:")
            print(
                f"python client/client.py --cert-dir {args.ca_dir}/clients/{client_id} --client-id {client_id}"
            )
            return 0

        # Handle listing clients
        elif args.list_clients:
            clients = ca.list_authorized_clients()
            print(f"Authorized clients ({len(clients)}):")
            for client_id, info in clients.items():
                print(
                    f"- {info['common_name']} (ID: {client_id}, Expires: {info['expires_at']})"
                )
            return 0

        # Handle revoking a certificate
        elif args.revoke_cert:
            if not args.client_id:
                print("Error: --client-id is required when revoking a certificate.")
                return 1

            if ca.revoke_client_certificate(args.client_id):
                print(f"Certificate for {args.client_id} has been revoked.")

                # Try to remove certificate files if they exist
                client_dir = os.path.join(args.ca_dir, "clients", args.client_id)
                if os.path.exists(client_dir):
                    try:
                        # Remove certificate files
                        for file in [
                            "client_cert.pem",
                            "client_key.pem",
                            "ca_cert.pem",
                        ]:
                            file_path = os.path.join(client_dir, file)
                            if os.path.exists(file_path):
                                os.remove(file_path)

                        # Try to remove the directory
                        os.rmdir(client_dir)
                        print(f"Certificate files removed from {client_dir}")
                    except Exception as e:
                        print(f"Warning: Could not fully remove certificate files: {e}")

                return 0
            else:
                print(f"No certificate found for {args.client_id}")
                return 1

    except Exception as e:
        print(f"Error: {e}")
        import traceback

        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
