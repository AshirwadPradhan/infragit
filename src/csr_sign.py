from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from getpass import getpass
import os
import sys
from pki_util import sign_csr

if __name__ == "__main__":
    cert_path = os.path.join(os.getcwd(),'src','')
    cert_server_name = sys.argv[1];

    csr_file = open(cert_path + cert_server_name + '-csr.pem', 'rb')
    csr = x509.load_pem_x509_csr(csr_file.read(), default_backend())

    ca_public_key_file = open(cert_path+'ca-public-key.pem', 'rb')
    ca_public_key = x509.load_pem_x509_certificate(ca_public_key_file.read(), default_backend())

    ca_private_key_file = open(cert_path+'ca-private-key.pem', 'rb')
    ca_private_key = serialization.load_pem_private_key(ca_private_key_file.read(),
                                                        getpass().encode('utf-8'),
                                                        default_backend())
    
    sign_csr(csr, ca_public_key, ca_private_key, cert_path + cert_server_name + '-public-key.pem')