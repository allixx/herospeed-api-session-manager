# Herospeed HTTP API session manager

I got my hands on NVR device with firmware copyrighted by Chinese  company named Herospeed (https://herospeed.net).

Its web interface is mostly built upon HTTP JSON API, and works rather well. API endpoints can be used to query various aspects of NVR state/functionality. All is good and well, except for one thing: for reasons unknown, instead of classic HTTP auth, they chose to implement two step authentication process, with deliberately nonsensical hashing steps involved, which are only good for improving obscurity withot real security benefit.

Pulling my hair while going through their frontend Javascript code, I came up with python implementation of used authentication scheme.

Work is done against API they advertise as v1.1.1, so I'm not sure whether this solution will work for older of newer implementations. There are notions that the same or very similar firmware may be used in other manufacturers devices, like Longse.

And yeah, why am I not surprised? Used hashing scheme indicates that they store user passwords in cleartext...

# Practical application

End-user part is handled by `hero_session_manager.py` script. Its `login` command allows to perform login and retrieve sessionID (`/api/session/login-capabilities` and `/api/session/login` endpoints), which then must be used as a cookie within further API requests.

To clean session data up, `logout` command is implemented as well (`/api/session/logout` endpoint).

To verify sessionID validity, use `verify` command (`/api/session/heart-beat` endpoint).

To discover existing API endpoints and their arguments, use Firefox Developer Tools while poking around WEB interface, they are not obfuscated.

# Internals

`hero_session.py` contains implementation of `HerospeedPasswordHash` class handling password hash derivation, `session_login`, `session_logout` and `session_verify` function helpers.

`hero_session_test.py` verifies correctness of password hash generation using known-good captured data.
