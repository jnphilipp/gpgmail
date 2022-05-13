# gpgmail

This tool can encrypt and decrypt emails using PGP/MIME. When encrypting,
the tool preserves all headers in the original email in the encrypted part, and
copies relevant headers to the output. When decrypting, any headers are
ignored, and only the encrypted headers are restored.

Encrypted email are not reencrypted. This is check based on the content type.


## Requirements

* Python 3.7 or newer
* pythond-gnupg
* gnupg


## Install

* from Source: ```make install```
* deb-Packet: ```make deb```


## Usage

### Postfix

Update ```smtp```, ```smtps``` and ```submission``` in ```/etc/postfix/master.cf```, add ```-o content_filter=gpgmail-pipe``` to the end, for example:

```
smtp    inet    n    -    -    -    -    smtpd -o content_filter=gpgmail-pipe
```

And add to the end of ```/etc/postfix/master.cf```:

```
gpgmail-pipe    unix    -    n    n    -    -    pipe
  flags=Rq user=gpgmail argv=/usr/bin/gpgmail-postfix --sign-encrypt --gnupghome /home/gpgmail/.gnupg --encrypt-headers --key KEYID --passphrase PASSPHRASE --recipient ${recipient} -oi -f ${sender}
```
