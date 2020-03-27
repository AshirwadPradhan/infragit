#Generate server's private key and generate csr

from pki_util import generate_private_key, generate_csr

if __name__ == "__main__":
    private_key = generate_private_key('server-private-key.pem', 'thisis_server_secret')

    generate_csr(private_key=private_key,
                        filename='server-csr.pem',
                        country='IN',
                        state='Rajasthan',
                        locality='Pilani',
                        org='BITS CSIS Department',
                        alt_names=['localhost', '127.0.0.1'],
                        hostname='infragit.com')