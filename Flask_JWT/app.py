import base64
import random
import string
from datetime import datetime, timedelta
from functools import wraps

import jwt
import psycopg2
import psycopg2.extras
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from flask import Flask, jsonify, request, session
from flask_cors import CORS
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)

app.config["SECRET_KEY"] = "CHOOSE A KEY"

key_cypher = app.config["SECRET_KEY"] + "2354235420"

app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=10)
CORS(app)

DB_HOST = ""
DB_PORT = 5432  # integer
DB_NAME = ""
DB_USER = ""
DB_PASS = ""

conn = psycopg2.connect(
    dbname=DB_NAME, user=DB_USER, password=DB_PASS, host=DB_HOST, port=DB_PORT
)


def cipherAES(password, iv):
    key = SHA256.new(password).digest()
    return AES.new(key, AES.MODE_CFB, iv)


def encryptor(plaintext, password):
    iv = Random.new().read(AES.block_size)
    return base64.b64encode(iv + cipherAES(password, iv).encrypt(plaintext))


def decryptor(ciphertext, password):
    d = base64.b64decode(ciphertext)
    iv, ciphertext = d[: AES.block_size], d[AES.block_size :]
    return cipherAES(password, iv).decrypt(ciphertext)


def random_char(y):
    return "".join(random.choice(string.ascii_letters) for x in range(y))


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if "x-access-token" in request.headers:
            token = request.headers["x-access-token"]

        if not token:
            resp = jsonify({"succes": False, "message": "Bad Request - Token Missing"})
            resp.status_code = 401
            return resp

        try:
            cursor_token = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            data = jwt.decode(
                token, app.config["SECRET_KEY"], options={"verify_signature": False}
            )

            key = data["key"][::-1]
            barcode = decryptor(data["barcode"].encode(), key.encode()).decode()

            sql = "SELECT barcode, username FROM users WHERE barcode=%s"
            sql_where = (barcode,)

            cursor_token.execute(sql, sql_where)
            row = cursor_token.fetchone()

            if row:
                current_user = {"username": row["username"], "barcode": row["barcode"]}
        except:
            resp = jsonify({"succes": False, "message": "Bad Request - Token Invalid"})
            resp.status_code = 401
            return resp

        return f(current_user, *args, **kwargs)

    return decorated


@app.route("/login", methods=["POST"])
def login():
    _content = request.json
    _username = _content["username"]
    _password = _content["password"]

    if _username and _password:
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

        sql = "SELECT barcode, username, password FROM users WHERE username=%s"
        sql_where = (_username,)

        cursor.execute(sql, sql_where)
        row = cursor.fetchone()
        username = row["username"]
        password = row["password"]
        barcode = row["barcode"]

        if row:
            if check_password_hash(password, _password):
                session["username"] = username
                cursor.close()

                key = random_char(len(username))

                token = jwt.encode(
                    {
                        "barcode": encryptor(barcode.encode(), key.encode()).decode(),
                        "key": key[::-1],
                        "exp": datetime.utcnow() + timedelta(minutes=30),
                    },
                    app.config["SECRET_KEY"],
                )

                return jsonify({"succes": True, "token": token})
            else:
                resp = jsonify(
                    {"succes": False, "message": "Bad Request - invalid password"}
                )
                resp.status_code = 400
                return resp
    else:
        resp = jsonify(
            {"succes": False, "message": "Bad Request - invalid credendtials"}
        )
        resp.status_code = 400
        return resp


@app.route("/check_token", methods=["POST"])
@token_required
def check_token(current_user):
    return {"current_user": current_user}


@app.route("/gen_hash", methods=["POST"])
def gen_hash():
    _content = request.json
    _password = _content["password"]

    if _password:
        return {"hash": generate_password_hash(_password)}


if __name__ == "__main__":
    app.run()
