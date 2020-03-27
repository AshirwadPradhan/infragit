import requests

def get_secret_message():
    url = 'https://localhost:5683'
    response = requests.get(url, verify='ca-public-key.pem')
    print(f'The secret message is : {response.text}')

if __name__ == "__main__":
    get_secret_message()