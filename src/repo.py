#!/usr/bin/env python3
# The REPOSITORY for the GATEWAY (third party server application)
from flask import Flask, request, jsonify
import os

SECRET_MESSAGE = 'very secret'
app = Flask(__name__)

@app.route('/')
def get_secret_message():
    return SECRET_MESSAGE

@app.route('/push', methods=['POST'])
def push():
    repo_name = request.json['repo_name']
    repo_data = request.json['data']
    c_path = os.path.join('src','dbrtest', repo_name)
    with open(c_path, 'wb+') as f: f.write(bytes.fromhex(repo_data))
    return jsonify({'repo_name': repo_name, 'status': 'OK'})

@app.route('/pull', methods=['POST'])
def pull():
    repo_name = request.json['repo_name']
    c_path = os.path.join('src','dbrtest', repo_name)
    with open(c_path, 'rb') as f: data = f.read()
    return jsonify({"data": data.hex()})


