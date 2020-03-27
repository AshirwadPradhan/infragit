#Generate CA's private and public key
# This enables us to become the CA

from pki_util import generate_private_key, generate_public_key

if __name__ == "__main__":
    private_key = generate_private_key('ca-private-key.pem', 'thisis_secret')

    generate_public_key(private_key=private_key,
                        filename='ca-public-key.pem',
                        country='IN',
                        state='Rajasthan',
                        locality='Pilani',
                        org='BITS CSIS Department',
                        hostname='bits-pilani-CA.ac.in')