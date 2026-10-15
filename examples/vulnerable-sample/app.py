"""Deliberately vulnerable sample for scanner demos. Do not deploy."""
import subprocess

import yaml
from flask import Flask, request

app = Flask(__name__)
DB_PASSWORD = "hunter2-demo-only"
payment_api_key = "q8Zr3vT6wLp0XyN4bM7sK2dF9hJ1cA5e"


@app.route("/ping")
def ping():
    host = request.args.get("host", "localhost")
    return subprocess.check_output("ping -c 1 " + host, shell=True)


@app.route("/config", methods=["POST"])
def config():
    return str(yaml.load(request.data))
