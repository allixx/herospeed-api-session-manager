#!/usr/bin/env python3

from hero_session import HerospeedPasswordHash


def test_password_hash():
    username = "remote"
    password = "PFpM4JZ3"

    login_capabilities = {
        "code": 0,
        "msg": None,
        "data": {
            "encryptionType": ["sha256-1"],
            "sessionID": "ab99bdc7f1f3607dd7d3a10d55611c2c",
            "param": {
                "challenge": "865cf746c11cd8e599413dc95660fd17",
                "iterations": 100,
                "enableIteration": True,
                "salt": "2bdc076cdd799a4f59cd5f75769e7d99",
            },
        },
    }

    debug_timestamp = "2025-02-19T21:02:42"
    debug_password_hash = (
        "6f72fb9aae8fa295ec0a264a583e6580ea9ec2434b74683aff900506f9db4f97"
    )

    password_hash = HerospeedPasswordHash(
        username=username,
        password=password,
        salt=login_capabilities["data"]["param"]["salt"],
        challenge=login_capabilities["data"]["param"]["challenge"],
        enable_iteration=login_capabilities["data"]["param"]["enableIteration"],
        iterations=login_capabilities["data"]["param"]["iterations"],
        timestamp=debug_timestamp,
    )

    hash = password_hash.derive()
    timestamp = password_hash.get_timestamp()

    assert hash == debug_password_hash, "Password hash incorrect"
    assert timestamp == debug_timestamp, "Timestamp incorrect"

    print("Hash calculation test passsed")


def main():
    test_password_hash()


if __name__ == "__main__":
    main()
