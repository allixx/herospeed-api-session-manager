#!/usr/bin/env python3

import base64
import datetime
import hashlib
import json
from http import HTTPStatus
from urllib import request

DEBUG = False
TIMEOUT = 5
HEADERS = {
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
}


if DEBUG:
    import urllib

    http_handler = urllib.request.HTTPHandler(debuglevel=1)
    opener = urllib.request.build_opener(http_handler)
    urllib.request.install_opener(opener)


class HerospeedPasswordHash:
    """Derive password hash required for session_id retrieval"""

    def __init__(
        self,
        username,
        password,
        salt,
        challenge,
        enable_iteration,
        iterations,
        timestamp=None,
    ):
        self.username = username
        self.password = password
        self.salt = salt
        self.challenge = challenge
        self.enable_iteration = enable_iteration
        self.iterations = iterations
        self.timestamp = timestamp

    @staticmethod
    def _hex_digest_to_string(hashsum):
        # encoding as Latin-1 as full range 0-255 chars are expected
        return bytearray.fromhex(hashsum).decode("Latin-1")

    def _round_one(self):
        if self.timestamp is None:
            self.timestamp = (
                datetime.datetime.now(tz=datetime.timezone.utc)
                .replace(microsecond=0)
                .isoformat()
            )

        return base64.b64encode(self.timestamp.encode()).decode()

    def _round_two(self, hashsum):
        string = self.username + self.salt + hashsum + self.password
        sha256sum = hashlib.sha256()
        sha256sum.update(string.encode())
        return sha256sum.hexdigest()

    @staticmethod
    def _round_three(hashsum, challenge):
        string = HerospeedPasswordHash._hex_digest_to_string(hashsum) + challenge
        sha256sum = hashlib.sha256()
        #  Latin-1 encoding from hex_digest_to_string
        sha256sum.update(string.encode("Latin-1"))
        return sha256sum.hexdigest()

    def _round_four(self, hashsum):
        for _ in range(self.iterations):
            hashsum = self._round_three(hashsum, "")

        return hashsum

    def derive(self):
        """Perform all obfuscation steps"""
        hashsum = self._round_one()
        hashsum = self._round_two(hashsum)
        hashsum = self._round_three(hashsum, self.challenge)

        if self.enable_iteration:
            hashsum = self._round_four(hashsum)

        return hashsum

    def get_timestamp(self):
        return self.timestamp


def session_login(host, port, credentials, timeout=TIMEOUT):
    """Retrieve session ID"""
    username, password = credentials.split(":")

    # get login capabilities
    url = f"{host}:{port}/api/session/login-capabilities"
    data = {"action": "get", "data": {"username": username}}

    form_data = json.dumps(data).encode()
    req = request.Request(
        url=url,
        data=form_data,
        headers=HEADERS,
    )

    password_hash = timestamp = session_id = encryption_type = None

    with request.urlopen(req, timeout=timeout) as response:
        # Expected response
        # {
        #     "code":0,
        #     "msg":"None",
        #     "data":{
        #         "encryptionType":[
        #             "sha256-1"
        #         ],
        #         "sessionID":"f75e0a12b4c4db61cf3e45cfd2347c64",
        #         "param":{
        #             "challenge":"c8aa8ae6769fb64e18326121aff1540f",
        #             "iterations":100,
        #             "enableIteration":true,
        #             "salt":"dd51b849f74d6d0fe91207716733e64e"
        #         }
        #     }
        # }
        body = json.loads(response.read())["data"]

        if DEBUG:
            print(body)

        session_id = body["sessionID"]
        encryption_type = body["encryptionType"]

        herospeed_password_hash = HerospeedPasswordHash(
            username=username,
            password=password,
            salt=body["param"]["salt"],
            challenge=body["param"]["challenge"],
            enable_iteration=body["param"]["enableIteration"],
            iterations=body["param"]["iterations"],
        )

        password_hash = herospeed_password_hash.derive()
        timestamp = herospeed_password_hash.get_timestamp()

    # perform login
    url = f"{host}:{port}/api/session/login"
    data = {
        "action": "set",
        "data": {
            "username": username,
            "loginEncryptionType": encryption_type[0],
            "password": password_hash,
            "sessionID": session_id,
            "datetime": timestamp,
        },
    }

    form_data = json.dumps(data).encode()
    req = request.Request(url=url, data=form_data, headers=HEADERS)

    session_id = None

    with request.urlopen(req, timeout=timeout) as response:
        # Expected response
        # {
        #     "code":0,
        #     "msg":null,
        #     "data":{
        #         "cookie":"sessionID=fe4368c1143e82a30ecc4d79d75e7744"
        #     }
        # }
        if response.status == HTTPStatus.OK and response.reason == "OK":
            body = json.loads(response.read())

            if DEBUG:
                print(body)

            response_code = body.get("code", -1)
            if response_code != 0:
                error = f"Invalid login response code: {response_code}"
                raise ValueError(error)

            _, session_id = body["data"]["cookie"].split("=")

    return session_id


def session_logout(host, port, session_id, timeout=TIMEOUT):
    """Log out from session ID"""
    url = f"{host}:{port}/api/session/logout"
    data = {"action": "set", "data": {"cookie": f"sessionID={session_id}"}}

    headers = HEADERS.copy()
    headers["Cookie"] = f"sessionID={session_id}"

    form_data = json.dumps(data).encode()
    req = request.Request(url=url, data=form_data, headers=headers)

    with request.urlopen(req, timeout=timeout) as response:
        if DEBUG:
            body = json.loads(response.read())
            print(body)


def session_verify(host, port, session_id, timeout=TIMEOUT):
    """Verify session ID validity"""
    url = f"{host}:{port}/api/session/heart-beat"
    data = {"operaType": "checkSessionHeart"}

    headers = HEADERS.copy()
    headers["Cookie"] = f"sessionID={session_id}"

    form_data = json.dumps(data).encode()
    req = request.Request(url=url, data=form_data, headers=headers)

    request.urlopen(req, timeout=timeout)
