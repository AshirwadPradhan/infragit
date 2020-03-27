# Utility Module
# Provides methods
#           1. Generate private key
#           2. Generate X509 certificate for the self-signing CA (here the organization is the CA)
#           3. Generate X509 for the server hosted by the organization
#           4. Sign the CSR of the server

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes

def generate_private_key(filename:str, passphare:str):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    utf8_pass = passphare.encode('utf-8')
    algo = serialization.BestAvailableEncryption(utf8_pass)

    with open(filename, 'wb') as keyfile:
        keyfile.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                encryption_algorithm=algo))
    
    return private_key

def generate_public_key(private_key, filename:str, **kwargs):

    # Self-Signing CA
    subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, kwargs['country']),
                        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, kwargs['state']),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, kwargs['locality']),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, kwargs['org']),
                        x509.NameAttribute(NameOID.COMMON_NAME, kwargs['hostname'])])
    
    # Issuer and subject is same becouse they are self-signed CA
    issuer = subject
    valid_from = datetime.utcnow() - timedelta(days=2)
    valid_to = valid_from + timedelta(days=365)

    builder = (x509.CertificateBuilder()
                .subject_name(subject)
                .issuer_name(issuer)
                .public_key(private_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(valid_from)
                .not_valid_after(valid_to))
    builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
    
    public_key = builder.sign(private_key, hashes.SHA256(), default_backend())

    with open(filename, 'wb') as certfile:
        certfile.write(public_key.public_bytes(serialization.Encoding.PEM))
    
    return public_key

def generate_csr(private_key, filename, **kwargs):

    # Generate the CSR for the server
    subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, kwargs['country']),
                        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, kwargs['state']),
                        x509.NameAttribute(NameOID.LOCALITY_NAME, kwargs['locality']),
                        x509.NameAttribute(NameOID.ORGANIZATION_NAME, kwargs['org']),
                        x509.NameAttribute(NameOID.COMMON_NAME, kwargs['hostname'])])
    
    alt_names = []
    for name in kwargs.get('alt_names', []):
        alt_names.append(x509.DNSName(name))
    san = x509.SubjectAlternativeName(alt_names)

    builder = (x509.CertificateSigningRequestBuilder()
                .subject_name(subject)
                .add_extension(san, critical=False))
    
    csr = builder.sign(private_key, hashes.SHA256(), default_backend())

    with open(filename, 'wb') as csrfile:
        csrfile.write(csr.public_bytes(serialization.Encoding.PEM))
    
    return csr
    
def sign_csr(csr, ca_public_key, ca_private_key, filename):

    #Sign the csr for the server by CA
    valid_from = datetime.utcnow() - timedelta(days=1)
    valid_to = valid_from + timedelta(days=60)

    builder = (x509.CertificateBuilder()
                .subject_name(csr.subject)
                .issuer_name(ca_public_key.subject)
                .public_key(csr.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(valid_from)
                .not_valid_after(valid_to))
    
    for extension in csr.extensions:
        builder = builder.add_extension(extension.value, extension.critical)
    
    public_key = builder.sign(private_key=ca_private_key,
                                algorithm=hashes.SHA256(),
                                backend=default_backend())
    
    with open(filename, 'wb') as keyfile:
        keyfile.write(public_key.public_bytes(serialization.Encoding.PEM))