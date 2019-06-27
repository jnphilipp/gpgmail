# gpgmail

This tool can encrypt and decrypt emails using PGP/MIME. When encrypting,
the tool preserves all headers in the original email in the encrypted part, and
copies relevant headers to the output. When decrypting, any headers are
ignored, and only the encrypted headers are restored.

Encrypted email are not reencrypted. This is check based on the content type.


## Requirements

* Python 3.6 or newer (3.7 recommended)
* gnupg


## Install

* from Source: ```make install```
* deb-Packet: ```make deb```
