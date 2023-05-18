import io
import os
import sys

from flask import Flask, render_template, request, send_file
import asyncio
import time
import algorithms
import json

app = Flask(__name__)


@app.route('/')
def index():  # put application's code here
    return render_template("index.html")


def switch_algorithm(algorithm, message, key, encrypt: bool):
    match algorithm:
        case "aes":
            if encrypt:
                return algorithms.aes_encrypt(message, key)
            else:
                return algorithms.aes_decrypt(message, key)
        case "des":
            if encrypt:
                return algorithms.des_encrypt(message, key)
            else:
                return algorithms.des_decrypt(message, key)
        case _:
            return ""


@app.route("/encrypt/<algorithm>")
def encrypt_text(algorithm):
    req = request.json
    message = req["message"]
    key = req["key"]

    iv = ""

    encrypted = switch_algorithm(algorithm, message, key, True)

    response = {
        "encrypted": str(encrypted).strip()
    }

    return response


@app.route("/encrypt/<algorithm>/file")
def encrypt_file(algorithm):
    file = request.files.get("file")
    key = request.form["key"]

    file.save(os.path.join(app.root_path, 'static\\temp\\original\\' + file.filename))

    file_content = io.open("./static/temp/original/" + file.filename, "rb")

    message = file_content.read()

    file.close()

    print(message, file=sys.stdout)

    encrypted = switch_algorithm(algorithm, message, key, True)

    encrypted_file = io.open("./static/temp/encrypted/" + file.filename + ".enc", "wb")

    encrypted_file.write(encrypted.encode())

    encrypted_file.close()

    return send_file("./static/temp/encrypted/" + file.filename + ".enc")


@app.route("/decrypt/<algorithm>")
def decrypt_text(algorithm):
    req = request.json

    encrypted = req["encrypted"]
    key = req["key"]

    message = switch_algorithm(algorithm, encrypted, key, False)

    response = {
        "message": str(message)
    }

    return response


@app.route("/decrypt/<algorithm>/file")
def decrypt_file(algorithm):
    file = request.files.get("file")
    key = request.form["key"]

    file.save(os.path.join(app.root_path, 'static\\temp\\encrypted\\' + file.filename))

    file_content = io.open("./static/temp/encrypted/" + file.filename, "rb")

    encrypted = file_content.read()

    file.close()

    print(encrypted, file=sys.stdout)

    decrypted = switch_algorithm(algorithm, encrypted, key, False)

    encrypted_file = io.open("./static/temp/original/decrypted_" + file.filename.removesuffix(".enc"), "wb")

    encrypted_file.write(decrypted)

    encrypted_file.close()

    return send_file("./static/temp/original/decrypted_" + file.filename.removesuffix(".enc"))


if __name__ == '__main__':
    app.run()
