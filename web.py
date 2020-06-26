#!/usr/bin/python3

from flask import Flask, request, abort, jsonify


app = Flask(__name__)

@app.route("/")
def index():
    return "ok"
