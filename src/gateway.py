# The GATEWAY for the client (entry point to the application)
from flask import Flask

SECRET_MESSAGE = 'very secret'
app = Flask(__name__)

@app.route('/')
def get_secret_message():
    return SECRET_MESSAGE