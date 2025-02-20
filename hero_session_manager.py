#!/usr/bin/env python3

import argparse
import sys

from hero_session import session_login, session_logout, TIMEOUT


def parse_args():
    def add_common_args(parser):
        parser.add_argument(
            "--host", required=True, help="Host to connect to, including protocol"
        )
        parser.add_argument(
            "--port", required=True, type=int, help="Port number to connect to"
        )
        parser.add_argument(
            "--timeout",
            required=False,
            type=int,
            default=TIMEOUT,
            help=f"Connection timeout in seconds, defaults to {TIMEOUT}",
        )

    parser = argparse.ArgumentParser(
        description="Herospeed API session manager",
    )
    subparsers = parser.add_subparsers(dest="command", help="command")

    login_parser = subparsers.add_parser("login", help="Login and retrieve session_id")
    login_parser.add_argument(
        "--credentials",
        required=True,
        help="Credentials pair joined by semicolon (username:password)",
    )
    add_common_args(login_parser)

    logout_parser = subparsers.add_parser(
        "logout", help="Logout from specified session_id"
    )
    logout_parser.add_argument("--session_id", required=True)
    add_common_args(logout_parser)

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
    else:
        return parser.parse_args()


def main():
    args = parse_args()

    if args.command == "login":
        session_id = session_login(
            host=args.host,
            port=args.port,
            credentials=args.credentials,
            timeout=args.timeout,
        )
        print(session_id)
    else:
        session_logout(
            host=args.host,
            port=args.port,
            session_id=args.session_id,
            timeout=args.timeout,
        )


if __name__ == "__main__":
    main()
