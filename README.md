# Herospeed HTTP API session manager

I got my hands on NVR device with firmware copyrighted by Chinese company named Herospeed (https://herospeed.net).

Its web interface is mostly built upon HTTP JSON API, and works rather well. API endpoints can be used to query various aspects of NVR state/functionality. All is good and well, except for one thing: for reasons unknown, instead of classic HTTP auth, they chose to implement two step authentication process, with deliberately nonsensical hashing steps involved, which are only good for improving obscurity withot real security benefit.

Pulling my hair while going through their frontend Javascript code, I came up with python implementation of used authentication scheme.

Work is done against API they advertise as v1.1.1, so I'm not sure whether this solution will work for older of newer implementations. There are notions that the same or very similar firmware may be used by other manufacturers, like Longse.

And yeah, why am I not surprised? Used hashing scheme indicates that they store user passwords in cleartext...

# Practical application

End-user part is handled by `hero_session_manager.py` script. Its `login` command performs login and retrieves sessionID, which then must be used as a cookie with further API requests.

To verify sessionID validity, use `verify` command (`/api/session/heart-beat` endpoint).

To clean session data up, `logout` command is implemented as well (`/api/session/logout` endpoint). Logout is not strictly necessary, as session timeout seems to be quite low (a few minutes).

To discover existing API endpoints and their arguments, use any modern browser's Developer Tools while poking around WEB interface, they are not obfuscated.

# Internals

SessionID retrieval is performed by utilizing `/api/session/login-capabilities` and `/api/session/login` device endpoints.

`hero_session.py` contains implementation of `HerospeedPasswordHash` class handling password hash derivation, `session_login`, `session_logout` and `session_verify` function helpers.

`tests/test_hero_session.py` verifies correctness of password hash generation using known-good captured data.

Implementation does not have any error handling and is meant to have illustrative purpose, although wrapped in exception handlers, it's used in real life and seems to work fairly well.
