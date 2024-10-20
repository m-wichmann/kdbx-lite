# kdbx-lite
Minmal implementation of the KeePassXC data format (kdbx). The implementation is based on the official documentation: https://keepass.info/help/kb/kdbx.html. The external libraries pycryptodome and argon2 are used for the encryption algorithms.

WARNING: Do not use this for sensitive data! This is a toy project, not a secure implementation of a password manager.


## Installation and usage (using virtual environment)
> python -m venv venv
> ./venv/bin/python -m pip install -r requirements.txt
> ./venv/bin/python kdbx_lit.py input.kdbx "password"
