#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: ft=python fileencoding=utf-8 sts=4 sw=4 et:
# Copyright (C) 2019-2022 J. Nathanael Philipp (jnphilipp) <nathanael@philipp.land>
#
# This file is part of gpgmail.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
"""Tests for gpgmail."""


import gnupg
import re
import socket
import unittest

from subprocess import Popen, PIPE
from tempfile import NamedTemporaryFile, TemporaryDirectory


class GPGMailTests(unittest.TestCase):
    """gpgmail tests."""

    def setUp(self):
        """Set up test case, create GPG key."""
        self.temp_gpg_homedir = TemporaryDirectory()
        gpg = gnupg.GPG(gnupghome=self.temp_gpg_homedir.name)

        gpgmail_input = gpg.gen_key_input(
            name_real="gpgmail",
            name_email="gpgmail@example.com",
            key_curve="cv25519",
            key_usage="encrypt,sign,auth",
            passphrase="test",
            expire_date="1y",
        )
        gpgmail_key = gpg.gen_key(gpgmail_input)
        self.assertIsNotNone(gpgmail_key)
        self.assertEqual("ok", gpgmail_key.status)
        self.key_id = gpg.list_keys(True)[0]["keyid"]

        alice_input = gpg.gen_key_input(
            name_real="Alice",
            name_email="alice@example.com",
            key_type="RSA",
            key_length=4096,
            key_usage="",
            subkey_type="RSA",
            subkey_length=4096,
            passphrase="test",
            subkey_usage="encrypt,sign,auth",
            expire_date="1y",
        )
        alice_key = gpg.gen_key(alice_input)
        self.assertIsNotNone(alice_key)
        self.assertEqual("ok", alice_key.status)

    def tearDown(self):
        """Tear down test case, clean gpg home dir."""
        self.temp_gpg_homedir.cleanup()

    def test_encrypt_decrypt(self):
        """Test encryption and decryption."""
        mail = (
            "Return-Path: <alice@example.com>\nReceived: from example.com (example.com "
            "[127.0.0.1])\n    by example.com (Postfix) with ESMTPSA id E8DB612009F\n"
            "    for <alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\n"
            'Content-Type: text/plain; charset="utf-8"\nMIME-Version: 1.0\n'
            "Content-Transfer-Encoding: 7bit\nSubject: Test\nFrom: alice@example.com\n"
            "To: alice@example.com\nDate: Tue, 07 Jan 2020 19:30:03 -0000\nMessage-ID: "
            "<123456789.123456.123456789@example.com>\n\nThis is a test message."
        )
        msg = "This is a test message."

        p = Popen(
            [
                "./gpgmail",
                "-e",
                "alice@example.com",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-k",
                self.key_id,
                "-p",
                "test",
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted, stderr = p.communicate(input=mail)
        self.assertNotIn(msg, encrypted)
        self.assertEqual("", stderr)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                encrypted,
            )
        )

        p = Popen(
            [
                "./gpgmail",
                "-k",
                self.key_id,
                "-p",
                "test",
                "-d",
                "--gnupghome",
                self.temp_gpg_homedir.name,
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        decrypted, stderr = p.communicate(input=encrypted)
        self.assertIn(msg, decrypted)
        self.assertEqual("", stderr)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                decrypted,
            )
        )
        regex = (
            r'Content-Type:\s+multipart/mixed;\s+protected-headers="v1";\s+boundary="=+'
            r'\d+==".+?--=+\d+==\nContent-Type:\s+text/rfc822-headers;\s+protected-head'
            r'ers="v1"\nContent-Disposition: inline\n(Subject:.+?\n|From:.+?\n|Message-'
            r"ID:.+?\n|Date:.+?\n|To:.+?\n)+\n\n--=+\d+==\n.+?\n\nThis is a test messag"
            r"e\.\n--=+\d+==--\n"
        )
        self.assertIsNotNone(re.fullmatch(regex, decrypted, flags=re.S))

        mail = (
            "Return-Path: <alice@example.com>\nReceived: from example.com (example.com "
            "[127.0.0.1])\n    by example.com (Postfix) with ESMTPSA id E8DB612009F\n"
            "    for <alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\n"
            'Content-Type: text/plain; charset="utf-8"\nMIME-Version: 1.0\n'
            "Content-Transfer-Encoding: quoted-printable\nSubject: Test\nFrom: "
            "alice@example.com\nTo: alice@example.com\nDate: Tue, 07 Jan 2020 "
            "19:30:03 -0000\nMessage-ID: <123456789.123456.123456789@example.com>\n\n"
            "Z p=C5=9Bija=C5=9Belnym p=C3=B3strowom\nMit freundlichen Gr=C3=BC=C3=9Fen"
        )

        p = Popen(
            [
                "./gpgmail",
                "-e",
                "alice@example.com",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-k",
                self.key_id,
                "-p",
                "test",
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted, stderr = p.communicate(input=mail)
        self.assertNotIn(
            "Z p=C5=9Bija=C5=9Belnym p=C3=B3strowom\nMit freundlichen Gr=C3=BC=C3=9Fen",
            encrypted,
        )
        self.assertNotIn("Z pśijaśelnym póstrowom\nMit freundlichen Grüßen", decrypted)
        self.assertEqual("", stderr)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                encrypted,
            )
        )

        p = Popen(
            [
                "./gpgmail",
                "-p",
                "test",
                "-k",
                self.key_id,
                "-d",
                "--gnupghome",
                self.temp_gpg_homedir.name,
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        decrypted, stderr = p.communicate(input=encrypted)
        self.assertIn("Z pśijaśelnym póstrowom\nMit freundlichen Grüßen", decrypted)
        self.assertEqual("", stderr)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                decrypted,
            )
        )
        regex = (
            r'Content-Type:\s+multipart/mixed;\s+protected-headers="v1";\s+boundary="=+'
            r'\d+==".+?--=+\d+==\nContent-Type:\s+text/rfc822-headers;\s+protected-head'
            r'ers="v1"\nContent-Disposition: inline\n(Subject:.+?\n|From:.+?\n|Message-'
            r"ID:.+?\n|Date:.+?\n|To:.+?\n)+\n\n--=+\d+==\n.+?\n\nZ pśijaśelnym póstrow"
            r"om\nMit freundlichen Grüßen\n--=+\d+==--\n"
        )
        self.assertIsNotNone(re.fullmatch(regex, decrypted, flags=re.S))

        mail = (
            "From: <mail@sender.com>\nTo: <mail@example.com>\nSubject: Test\nDate: "
            'Thu, 27 Jun 2019 09:42:57 +0200\nContent-Type: text/plain; charset="UTF-8"'
            "\nMIME-Version: 1.0\n\nThis is a message, with some text. ÄÖÜäöüßłµøǒšé\n"
            "\nZ pśijaśelnym póstrowom\nMit freundlichen Grüßen\n\ngpgmail"
        )
        msg = (
            "This is a message, with some text. ÄÖÜäöüßłµøǒšé\n\nZ pśijaśelnym póstrowo"
            "m\nMit freundlichen Grüßen\n\ngpgmail"
        )

        p = Popen(
            [
                "./gpgmail",
                "-e",
                "alice@example.com",
                "--gnupghome",
                self.temp_gpg_homedir.name,
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted, stderr = p.communicate(input=mail)
        self.assertNotIn(msg, encrypted)
        self.assertEqual("", stderr)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                encrypted,
            )
        )

        p = Popen(
            [
                "./gpgmail",
                "-p",
                "test",
                "-k",
                self.key_id,
                "-d",
                "--gnupghome",
                self.temp_gpg_homedir.name,
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        decrypted, stderr = p.communicate(input=encrypted)
        self.assertIn(msg, decrypted)
        self.assertEqual("", stderr)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                decrypted,
            )
        )
        regex = (
            r'Content-Type:\s+multipart/mixed;\s+protected-headers="v1";\s+boundary="=+'
            r'\d+==".+?--=+\d+==\nContent-Type:\s+text/rfc822-headers;\s+protected-head'
            r'ers="v1"\nContent-Disposition: inline\n(Subject:.+?\n|From:.+?\n|Message-'
            r"ID:.+?\n|Date:.+?\n|To:.+?\n)+\n\n--=+\d+==\n.+?\n\nThis is a message, wi"
            r"th some text. ÄÖÜäöüßłµøǒšé\n\nZ pśijaśelnym póstrowom\nMit freundlichen "
            r"Grüßen\n\ngpgmail\n--=+\d+==--\n"
        )
        self.assertIsNotNone(re.fullmatch(regex, decrypted, flags=re.S))

    def test_sign(self):
        """Test signing."""
        gpg = gnupg.GPG(gnupghome=self.temp_gpg_homedir.name)

        mail = (
            "Return-Path: <alice@example.com>\nReceived: from example.com (example.com "
            "[127.0.0.1])\n    by example.com (Postfix) with ESMTPSA id E8DB612009F\n"
            "    for <alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\n"
            'Content-Type: text/plain; charset="utf-8"\nMIME-Version: 1.0\nContent-'
            "Transfer-Encoding: 7bit\nSubject: Test\nFrom: alice@example.com\nTo: alice"
            "@example.com\nDate: Tue, 07 Jan 2020 19:30:03 -0000\nMessage-ID:\n <123456"
            "789.123456.123456789@example.com>\n\nThis is a test message."
        )
        msg = "This is a test message."

        p = Popen(
            [
                "./gpgmail",
                "-s",
                "alice@example.com",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-k",
                self.key_id,
                "-p",
                "test",
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        signed, stderr = p.communicate(input=mail)
        self.assertIn(msg, signed)
        self.assertEqual("", stderr)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}", signed
            )
        )

        m = re.search(
            r"--=+\d+==\n(?P<data>.+?)--=+\d+==--.+?(?P<signature>-+BEGIN PGP "
            r"SIGNATURE-+.+?-+END PGP SIGNATURE-+)",
            signed,
            flags=re.S,
        )
        self.assertIsNotNone(m)
        with NamedTemporaryFile("wt") as f:
            f.write(m.group("signature"))

            verified = gpg.verify_data(f.name, m.group("data").encode("utf8"))
            self.assertIsNotNone(verified.status)
            self.assertNotEqual("bad signature", verified.status)

        regex = (
            r'Content-Type:\s+multipart/signed;\s+micalg="pgp-sha512";\s+protocol="appl'
            r'ication/pgp-signature";\s+boundary="=+\d+=="\n.+?\n\n--=+\d+==\nContent-T'
            r'ype:\s+multipart/mixed;\s+protected-headers="v1";\s+boundary="=+\d+=="\n'
            r".+?\n\n--=+\d+==\nContent-Type:\s+text/rfc822-headers;\s+protected-header"
            r's="v1"\nContent-Disposition: inline\n(Date:.+?\n|Message-ID:.+?\n|Subject'
            r":.+?\n|To:.+?\n|From:.+?\n)+\n\n--=+\d+==\nContent-Type: text/plain; char"
            r'set="utf-8".+?This is a test message\.\n--=+\d+==--\n\n--=+\d+==\nContent'
            r'-Type: application/pgp-signature; name="signature\.asc"\nContent-Descript'
            r"ion: OpenPGP digital signature\nContent-Disposition: attachment; filename"
            r'="signature\.asc"\n\n-+BEGIN PGP SIGNATURE-+\n\n[\w\n\+/=]+\n-+END PGP SI'
            r"GNATURE-+\n\n--=+\d+==--\n"
        )
        self.assertIsNotNone(re.fullmatch(regex, signed, flags=re.S))

        mail = (
            "From: <mail@sender.com>\nTo: <mail@example.com>\nSubject: Test\nDate: "
            'Thu, 27 Jun 2019 09:42:57 +0200\nContent-Type: text/plain; charset="UTF-8"'
            "\nMIME-Version: 1.0\n\nThis is a message, with some text. ÄÖÜäöüßłµøǒšé\n"
            "\nZ pśijaśelnym póstrowom\nMit freundlichen Grüßen\n\ngpgmail"
        )
        msg = (
            "This is a message, with some text. ÄÖÜäöüßłµøǒšé\n\nZ pśijaśelnym póstrowo"
            "m\nMit freundlichen Grüßen\n\ngpgmail"
        )

        p = Popen(
            [
                "./gpgmail",
                "-s",
                "alice@example.com",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-k",
                self.key_id,
                "-p",
                "test",
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        signed, stderr = p.communicate(input=mail)
        self.assertIn(msg, signed)
        self.assertEqual("", stderr)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}", signed
            )
        )

        m = re.search(
            r"--=+\d+==\n(?P<data>.+?)--=+\d+==--.+?(?P<signature>-+BEGIN PGP "
            r"SIGNATURE-+.+?-+END PGP SIGNATURE-+)",
            signed,
            flags=re.S,
        )
        self.assertIsNotNone(m)
        with NamedTemporaryFile("wt") as f:
            f.write(m.group("signature"))

            verified = gpg.verify_data(f.name, m.group("data").encode("utf8"))
            self.assertIsNotNone(verified.status)
            self.assertNotEqual("bad signature", verified.status)

        regex = (
            r'Content-Type:\s+multipart/signed;\s+micalg="pgp-sha512";\s+protocol="appl'
            r'ication/pgp-signature";\s+boundary="=+\d+=="\n.+?\n\n--=+\d+==\nContent-T'
            r'ype:\s+multipart/mixed;\s+protected-headers="v1";\s+boundary="=+\d+=="\n'
            r".+?\n\n--=+\d+==\nContent-Type:\s+text/rfc822-headers;\s+protected-header"
            r's="v1"\nContent-Disposition: inline\n(Date:.+?\n|Message-ID:.+?\n|Subject'
            r":.+?\n|To:.+?\n|From:.+?\n)+\n\n--=+\d+==\nContent-Type: text/plain; char"
            r'set="UTF-8".+?This is a message, with some text. ÄÖÜäöüßłµøǒšé\n\nZ pśija'
            r"śelnym póstrowom\nMit freundlichen Grüßen\n\ngpgmail\n--=+\d+==--\n\n--=+"
            r'\d+==\nContent-Type: application/pgp-signature; name="signature\.asc"\nCo'
            r"ntent-Description: OpenPGP digital signature\nContent-Disposition: attach"
            r'ment; filename="signature\.asc"\n\n-+BEGIN PGP SIGNATURE-+\n\n[\w\n\+/=]+'
            r"\n-+END PGP SIGNATURE-+\n\n--=+\d+==--\n"
        )
        self.assertIsNotNone(re.fullmatch(regex, signed, flags=re.S))

    def test_sign_encrypt_decrypt(self):
        """Test signing, encryption and decryption."""
        gpg = gnupg.GPG(gnupghome=self.temp_gpg_homedir.name)

        mail = (
            "Return-Path: <alice@example.com>\nReceived: from example.com (example.com "
            "[127.0.0.1])\n    by example.com (Postfix) with ESMTPSA id E8DB612009F\n"
            "    for <alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\n"
            'Content-Type: text/plain; charset="utf-8"\n MIME-Version: 1.0\n'
            "Content-Transfer-Encoding: 7bit\nSubject: Test\nFrom: alice@example.com"
            "\nTo: alice@example.com\nDate: Tue, 07 Jan 2020 19:30:03 -0000\n"
            "Message-ID:\n <123456789.123456.123456789@example.com>\n\nThis is a "
            "test message."
        )
        msg = "This is a test message."

        p = Popen(
            [
                "./gpgmail",
                "-E",
                "alice@example.com",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-k",
                self.key_id,
                "-p",
                "test",
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted, stderr = p.communicate(input=mail)
        self.assertNotIn(msg, encrypted)
        self.assertEqual("", stderr)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                encrypted,
            )
        )

        p = Popen(
            [
                "./gpgmail",
                "-d",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-k",
                self.key_id,
                "-p",
                "test",
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        decrypted, stderr = p.communicate(input=encrypted)
        self.assertIn(msg, decrypted)
        self.assertEqual("", stderr)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                decrypted,
            )
        )

        m = re.search(
            r"--=+\d+==\n(?P<data>.+?)--=+\d+==--.+?(?P<signature>-+BEGIN PGP "
            r"SIGNATURE-+.+?-+END PGP SIGNATURE-+)",
            decrypted,
            flags=re.S,
        )
        self.assertIsNotNone(m)
        with NamedTemporaryFile("wt") as f:
            f.write(m.group("signature"))

            verified = gpg.verify_data(f.name, m.group("data").encode("utf8"))
            self.assertIsNotNone(verified.status)
            self.assertNotEqual("bad signature", verified.status)

        regex = (
            r'Content-Type:\s+multipart/signed;\s+micalg="pgp-sha512";\s+protocol="appl'
            r'ication/pgp-signature";\s+boundary="=+\d+=="\n.+?\n\n--=+\d+==\nContent-T'
            r'ype:\s+multipart/mixed;\s+protected-headers="v1";\s+boundary="=+\d+=="\n'
            r".+?\n\n--=+\d+==\nContent-Type:\s+text/rfc822-headers;\s+protected-header"
            r's="v1"\nContent-Disposition: inline\n(Date:.+?\n|Message-ID:.+?\n|Subject'
            r":.+?\n|To:.+?\n|From:.+?\n)+\n\n--=+\d+==\nContent-Type: text/plain; char"
            r'set="utf-8".+?This is a test message\.\n--=+\d+==--\n\n--=+\d+==\nContent'
            r'-Type: application/pgp-signature; name="signature\.asc"\nContent-Descript'
            r"ion: OpenPGP digital signature\nContent-Disposition: attachment; filename"
            r'="signature\.asc"\n\n-+BEGIN PGP SIGNATURE-+\n\n[\w\n\+/=]+\n-+END PGP SI'
            r"GNATURE-+\n\n--=+\d+==--\n"
        )
        self.assertIsNotNone(re.fullmatch(regex, decrypted, flags=re.S))

    def test_encryptheaders(self):
        """Test encryption of headers (RFC 822)."""
        gpg = gnupg.GPG(gnupghome=self.temp_gpg_homedir.name)

        mail = (
            "Return-Path: <alice@example.com>\nReceived: from example.com (example.com "
            + "[127.0.0.1])\n    by example.com (Postfix) with ESMTPSA id E8DB612009F\n"
            + "    for <alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\n"
            + 'Content-Type: text/plain; charset="utf-8"\nMIME-Version: 1.0\n'
            + "Content-Transfer-Encoding: 7bit\nSubject: Test\nFrom: alice@example.com"
            + "\nTo: alice@example.com\nDate: Tue, 07 Jan 2020 19:30:03 -0000\n"
            + "Message-ID: <123456789.123456.123456789@example.com>\n\nThis is a "
            + "test message."
        )
        msg = "This is a test message."

        p = Popen(
            [
                "./gpgmail",
                "-e",
                "alice@example.com",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-H",
                "--key",
                self.key_id,
                "-p",
                "test",
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted, stderr = p.communicate(input=mail)
        self.assertNotIn(msg, encrypted)
        self.assertEqual("", stderr)
        self.assertIn("Date: ...\n", encrypted)
        self.assertIn("From: ...\n", encrypted)
        self.assertIn("Message-ID: ...\n", encrypted)
        self.assertIn("Subject: ...\n", encrypted)
        self.assertIn("To: ...\n", encrypted)
        self.assertNotIn("Date: Tue, 07 Jan 2020 19:30:03 -0000\n", encrypted)
        self.assertNotIn("From: alice@example.com\n", encrypted)
        self.assertNotIn(
            "Message-ID: <123456789.123456.123456789@example.com>\n", encrypted
        )
        self.assertNotIn("Subject: Test\n", encrypted)
        self.assertNotIn("To: alice@example.com\n", encrypted)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                encrypted,
            )
        )

        p = Popen(
            [
                "./gpgmail",
                "-d",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-k",
                self.key_id,
                "-p",
                "test",
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        decrypted, stderr = p.communicate(input=encrypted)
        self.assertIn(msg, decrypted)
        self.assertEqual("", stderr)
        self.assertNotIn("Date: ...\n", decrypted)
        self.assertNotIn("From: ...\n", decrypted)
        self.assertNotIn("Message-ID: ...\n", decrypted)
        self.assertNotIn("Subject: ...\n", decrypted)
        self.assertNotIn("To: ...\n", decrypted)
        self.assertIn("Date: Tue, 07 Jan 2020 19:30:03 -0000\n", decrypted)
        self.assertIn("From: alice@example.com\n", decrypted)
        self.assertIn(
            "Message-ID: <123456789.123456.123456789@example.com>\n", decrypted
        )
        self.assertIn("Subject: Test\n", decrypted)
        self.assertIn("To: alice@example.com\n", decrypted)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                decrypted,
            )
        )

        mail = (
            "Return-Path: <alice@example.com>\nReceived: from example.com (example.com "
            + "[127.0.0.1])\n    by example.com (Postfix) with ESMTPSA id E8DB612009F\n"
            + "    for <alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\n"
            + 'Content-Type: text/plain; charset="utf-8"\nMIME-Version: 1.0\n'
            + "Content-Transfer-Encoding: quoted-printable\nSubject: Test\nFrom: "
            + "alice@example.com\nTo: alice@example.com\nDate: Tue, 07 Jan 2020 "
            + "19:30:03 -0000\nMessage-ID: <123456789.123456.123456789@example.com>\n\n"
            + "Z p=C5=9Bija=C5=9Belnym p=C3=B3strowomr\nMit freundlichen "
            + "Gr=C3=BC=C3=9Fen"
        )

        p = Popen(
            [
                "./gpgmail",
                "--encrypt-headers",
                "--sign-encrypt",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "alice@example.com",
                "--passphrase",
                "test",
                "--key",
                self.key_id,
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted, stderr = p.communicate(input=mail)
        self.assertNotIn(
            "Z p=C5=9Bija=C5=9Belnym p=C3=B3strowomr\n"
            + "Mit freundlichen Gr=C3=BC=C3=9Fen",
            encrypted,
        )
        self.assertEqual("", stderr)
        self.assertIn("Date: ...\n", encrypted)
        self.assertIn("From: ...\n", encrypted)
        self.assertIn("Message-ID: ...\n", encrypted)
        self.assertIn("Subject: ...\n", encrypted)
        self.assertIn("To: ...\n", encrypted)
        self.assertNotIn("Date: Tue, 07 Jan 2020 19:30:03 -0000\n", encrypted)
        self.assertNotIn("From: alice@example.com\n", encrypted)
        self.assertNotIn(
            "Message-ID: <123456789.123456.123456789@example.com>\n", encrypted
        )
        self.assertNotIn("Subject: Test\n", encrypted)
        self.assertNotIn("To: alice@example.com\n", encrypted)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                encrypted,
            )
        )

        p = Popen(
            [
                "./gpgmail",
                "--decrypt",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "--passphrase",
                "test",
                "--key",
                self.key_id,
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        decrypted, stderr = p.communicate(input=encrypted)
        self.assertIn("Z pśijaśelnym póstrowomr\nMit freundlichen Grüßen", decrypted)
        self.assertEqual("", stderr)
        self.assertNotIn("Date: ...\n", decrypted)
        self.assertNotIn("From: ...\n", decrypted)
        self.assertNotIn("Message-ID: ...\n", decrypted)
        self.assertNotIn("Subject: ...\n", decrypted)
        self.assertNotIn("To: ...\n", decrypted)
        self.assertIn("Date: Tue, 07 Jan 2020 19:30:03 -0000\n", decrypted)
        self.assertIn("From: alice@example.com\n", decrypted)
        self.assertIn(
            "Message-ID: <123456789.123456.123456789@example.com>\n", decrypted
        )
        self.assertIn("Subject: Test\n", decrypted)
        self.assertIn("To: alice@example.com\n", decrypted)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                decrypted,
            )
        )

        m = re.search(
            r"--=+\d+==\n(?P<data>.+?)--=+\d+==--.+?(?P<signature>-+BEGIN PGP "
            r"SIGNATURE-+.+?-+END PGP SIGNATURE-+)",
            decrypted,
            flags=re.S,
        )
        self.assertIsNotNone(m)
        with NamedTemporaryFile("wt") as f:
            f.write(m.group("signature"))

            verified = gpg.verify_data(f.name, m.group("data").encode("utf8"))
            self.assertIsNotNone(verified.status)
            self.assertNotEqual("bad signature", verified.status)

    def test_encryptfail(self):
        """Test encryption fails."""
        mail = (
            "Return-Path: <alice@example.com>\nReceived: from example.com (example.com "
            "[127.0.0.1])\n    by example.com (Postfix) with ESMTPSA id E8DB612009F\n"
            "    for <alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\n"
            'Content-Type: text/plain; charset="utf-8"\nMIME-Version: 1.0\n'
            "Content-Transfer-Encoding: 7bit\nSubject: Test\nFrom: alice@example.com"
            "\nTo: alice@example.com\nDate: Tue, 07 Jan 2020 19:30:03 -0000\n"
            "Message-ID: <123456789.123456.123456789@example.com>\n\nThis is a "
            "test message."
        )

        p = Popen(
            [
                "./gpgmail",
                "-e",
                "alice.do@example.com",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-H",
                "--key",
                self.key_id,
                "-p",
                "test",
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted, stderr = p.communicate(input=mail)
        self.assertEqual(mail, encrypted)
        self.assertEqual("Traceback (most recent call last):", stderr[:34])
        self.assertEqual(
            "\nRuntimeError: Could not encrypt message: invalid recipient\n",
            stderr[-60:],
        )

        mail = (
            "Return-Path: <alice@example.com>\nReceived: from example.com (example.com "
            "[127.0.0.1])\n    by example.com (Postfix) with ESMTPSA id E8DB612009F\n  "
            "  for <alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\nContent"
            '-Type: text/plain; charset="utf-8"\nMIME-Version: 1.0\nContent-Transfer-En'
            "coding: 8bit\nSubject: Test\nFrom: alice@example.com\nTo: alice@example.co"
            "m\nDate: Tue, 07 Jan 2020 19:30:03 -0000\nMessage-ID: <123456789.123456.12"
            "3456789@example.com>\n\nFür alle Räuber in der Röhn, es gibt ein neues Caf"
            "é.\nÄÖÜß\n\nZ pśijaśelnym póstrowom\nMit freundlichen Grüßen\ngpgmail"
        )

        p = Popen(
            [
                "./gpgmail",
                "-e",
                "alice.do@example.com",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-H",
                "--key",
                self.key_id,
                "-p",
                "test",
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted, stderr = p.communicate(input=mail)
        self.assertEqual(mail, encrypted)
        self.assertEqual("Traceback (most recent call last):", stderr[:34])
        self.assertEqual(
            "\nRuntimeError: Could not encrypt message: invalid recipient\n",
            stderr[-60:],
        )

    def test_sign_encrypt_decrypt_utf8(self):
        """Test signing, encryption and decryption with utf8 encoding."""
        gpg = gnupg.GPG(gnupghome=self.temp_gpg_homedir.name)

        mail = (
            "Return-Path: <alice@example.com>\nReceived: from example.com (example.com "
            "[127.0.0.1])\n    by example.com (Postfix) with ESMTPSA id E8DB612009F\n  "
            "  for <alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\nContent"
            '-Type: text/plain; charset="utf-8"\nMIME-Version: 1.0\nSubject: Test\nFrom'
            ": alice@example.com\nTo: alice@example.com\nDate: Tue, 07 Jan 2020 19:30:0"
            "3 -0000\nMessage-ID:\n <123456789.123456.123456789@example.com>\n\nFür all"
            "e Räuber in der Röhn, es gibt ein neues Café.\nÄÖÜß\n\nZ pśijaśelnym póstr"
            "owom\nMit freundlichen Grüßen\ngpgmail"
        )
        msg = (
            "Für alle Räuber in der Röhn, es gibt ein neues Café.\nÄÖÜß\n\nZ pśijaśelny"
            "m póstrowom\nMit freundlichen Grüßen\ngpgmail"
        )

        p = Popen(
            [
                "./gpgmail",
                "-E",
                "alice@example.com",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-p",
                "test",
                "--key",
                self.key_id,
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted, stderr = p.communicate(input=mail)
        self.assertNotIn(msg, encrypted)
        self.assertEqual("", stderr)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                encrypted,
            )
        )

        p = Popen(
            [
                "./gpgmail",
                "--key",
                self.key_id,
                "-p",
                "test",
                "-d",
                "--gnupghome",
                self.temp_gpg_homedir.name,
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        decrypted, stderr = p.communicate(input=encrypted)
        self.assertIn(msg, decrypted)
        self.assertEqual("", stderr)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                decrypted,
            )
        )

        m = re.search(
            r"--=+\d+==\n(?P<data>.+?)--=+\d+==--.+?(?P<signature>-+BEGIN PGP "
            r"SIGNATURE-+.+?-+END PGP SIGNATURE-+)",
            decrypted,
            flags=re.S,
        )
        self.assertIsNotNone(m)
        with NamedTemporaryFile("wt") as f:
            f.write(m.group("signature"))

            verified = gpg.verify_data(f.name, m.group("data").encode("utf8"))
            self.assertIsNotNone(verified.status)
            self.assertNotEqual("bad signature", verified.status)

        regex = (
            r'Content-Type:\s+multipart/signed;\s+micalg="pgp-sha512";\s+protocol="appl'
            r'ication/pgp-signature";\s+boundary="=+\d+==".+?--=+\d+==\nContent-Type:'
            r'\s+multipart/mixed;\s+protected-headers="v1";\s+boundary="=+\d+==".+?--=+'
            r'\d+==\nContent-Type: text/rfc822-headers; protected-headers="v1"\nContent'
            r"-Disposition: inline\n(Date:.+?\n|To:.+?\n|From:.+?\n|Message-ID:.+?\n|Su"
            r"bject:.+?\n)+\n\n--=+\d+==.+?Für alle Räuber in der Röhn, es gibt ein neu"
            r"es Café\.\nÄÖÜß\n\nZ pśijaśelnym póstrowom\nMit freundlichen Grüßen\ngpgm"
            r"ail\n--=+\d+==--\n\n--=+\d+==\nContent-Type: application/pgp-signature; n"
            r'ame="signature\.asc"\nContent-Description: OpenPGP digital signature\nCon'
            r'tent-Disposition: attachment; filename="signature\.asc"\n\n-+BEGIN PGP SI'
            r"GNATURE-+[\n\w\d\+/=]+-+END PGP SIGNATURE-+\n\n--=+\d+==--\n"
        )
        self.assertIsNotNone(re.fullmatch(regex, decrypted, flags=re.S))

    def test_multipart_message(self):
        """Test handling of multipart messages."""
        gpg = gnupg.GPG(gnupghome=self.temp_gpg_homedir.name)

        mail = (
            "Return-Path: <alice@example.com>\nReceived: from example.com (example.com "
            "[127.0.0.1])\n by example.com (Postfix) with ESMTPSA id E8DB612009F\n for "
            "<alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\nMessage-ID:"
            "\n <123456789.123456.123456789@example.com>\nSubject: Test\nFrom: "
            "alice@example.com\nTo: alice@example.com\nDate: Tue, 07 Jan 2020 "
            "19:30:03 -0000\nContent-Type: multipart/alternative; "
            'boundary="pCGCiOTgoFTJJwVyvskX"\nMIME-Version: 1.0\n\n'
            '--pCGCiOTgoFTJJwVyvskX\nContent-Type: text/plain; charset="UTF-8"\n'
            "Content-Transfer-Encoding: 8bit\n\nThis is a message, with some text."
            "\n\nZ pśijaśelnym póstrowom\nMit freundlichen Grüßen\n\ngpgmail\n"
            '--pCGCiOTgoFTJJwVyvskX\nContent-Type: text/html; charset="utf-8"\n'
            "Content-Transfer-Encoding: 8bit\n\n<html><head></head><body><div>"
            "This is a <b>message</b>, with some <i>text</i>.</div><div><br></div>"
            "<div>Z pśijaśelnym póstrowom</div><div>Mit freundlichen Grüßen</div>"
            "<div><br></div><div>gpgmail</div><div><span></span></div></body>"
            "</html>\n--pCGCiOTgoFTJJwVyvskX--"
        )
        msg = (
            "This is a message, with some text.\n\nZ pśijaśelnym póstrowom\n"
            "Mit freundlichen Grüßen\n\ngpgmail"
        )
        msg2 = (
            "<html><head></head><body><div>This is a <b>message</b>, with some <i>text"
            "</i>.</div><div><br></div><div>Z pśijaśelnym póstrowom</div><div>"
            "Mit freundlichen Grüßen</div><div><br></div><div>gpgmail</div><div>"
            "<span></span></div></body></html>"
        )

        p = Popen(
            [
                "./gpgmail",
                "-E",
                "-H",
                "alice@example.com",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-p",
                "test",
                "-k",
                self.key_id,
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted, stderr = p.communicate(input=mail)
        self.assertNotIn(msg, encrypted)
        self.assertNotIn(msg2, encrypted)
        self.assertEqual("", stderr)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                encrypted,
            )
        )

        p = Popen(
            [
                "./gpgmail",
                "-k",
                self.key_id,
                "-p",
                "test",
                "-d",
                "--gnupghome",
                self.temp_gpg_homedir.name,
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        decrypted, stderr = p.communicate(input=encrypted)
        self.assertIn(msg, decrypted)
        self.assertIn(msg2, decrypted)
        self.assertEqual("", stderr)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                decrypted,
            )
        )

        m = re.search(
            r"--=+\d+==\n(?P<data>.+?)--=+\d+==--.+?(?P<signature>-+BEGIN PGP "
            r"SIGNATURE-+.+?-+END PGP SIGNATURE-+)",
            decrypted,
            flags=re.S,
        )
        self.assertIsNotNone(m)
        with NamedTemporaryFile("wt") as f:
            f.write(m.group("signature"))

            verified = gpg.verify_data(f.name, m.group("data").encode("utf8"))
            self.assertIsNotNone(verified.status)
            self.assertNotEqual("bad signature", verified.status)

        regex = (
            r'Content-Type:\s+multipart/signed;\s+micalg="pgp-sha512";\s+protocol="appl'
            r'ication/pgp-signature";\s+boundary="=+\d+==".+?--=+\d+==\nContent-Type:'
            r'\s+multipart/mixed;\s+protected-headers="v1";\s+boundary="=+\d+==".+?--=+'
            r'\d+==\nContent-Type:\s+text/rfc822-headers;\s+protected-headers="v1"\nCon'
            r"tent-Disposition: inline\n(Subject:.+?\n|Date:.+?\n|From:.+?\n|Message-ID"
            r":.+?\n|To:.+?\n)+\n\n--=+\d+==\nContent-Type:\s+multipart/alternative;\s+"
            r'boundary="\w+"\n\n--\w+\nContent-Type: text/plain; charset="UTF-8"\nConte'
            r"nt-Transfer-Encoding: 8bit\n\nThis is a message, with some text\.\n\nZ pś"
            r"ijaśelnym póstrowom\nMit freundlichen Grüßen\n\ngpgmail\n--\w+\nContent-T"
            r'ype: text/html; charset="utf-8"\nContent-Transfer-Encoding: 8bit\n\n<html'
            r"><head></head><body><div>This is a <b>message</b>, with some <i>text</i>"
            r"\.</div><div><br></div><div>Z pśijaśelnym póstrowom</div><div>Mit freundl"
            r"ichen Grüßen</div><div><br></div><div>gpgmail</div><div><span></span></di"
            r"v></body></html>\n--\w+--\n\n--=+\d+==--\n\n--=+\d+==\nContent-Type: appl"
            r'ication/pgp-signature; name="signature\.asc"\nContent-Description: OpenPG'
            r'P digital signature\nContent-Disposition: attachment; filename="signature'
            r'\.asc"\n\n-+BEGIN PGP SIGNATURE-+[\d\w\n/=\+]+-+END PGP SIGNATURE-+\n\n--'
            r"=+\d+==--\n"
        )
        self.assertIsNotNone(re.fullmatch(regex, decrypted, flags=re.S))

        mail = (
            "Return-Path: <bob@example.com>\nX-Original-To: alice@example.com\n"
            "Delivered-To: alice@example.com\nReceived: from example.com (example.com"
            " [127.0.0.1]) by example.com (Postfix) with ESMTPSA id E8DB612009F for "
            "<alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\nMessage-ID:"
            " <123456789.123456.123456789@example.com>\nFrom: bob@example.com\nTo: "
            "alice@example.com\nDate: Tue,  7 Jan 2020 19:30:03 +0200\nReferences: "
            "<123456789.123456.123456789.ABCDEF@example.com>\nContent-Type: "
            'multipart/mixed; boundary="=-spsfm35OzlCD03QPN9Hr"\nMIME-Version: 1.0\n'
            "Subject: Fwd: Test\n--=-spsfm35OzlCD03QPN9Hr\nContent-Type: text/plain\n"
            "Content-Transfer-Encoding: 7bit\nForwarded Message\n"
            "--=-spsfm35OzlCD03QPN9Hr\nContent-Disposition: inline\n"
            "Content-Description: Weitergeleitete Nachricht =?UTF-8?Q?=E2=80=93?= "
            "Test\nContent-Type: message/rfc822\nReturn-Path: <charlie@example.com>\n"
            "Received: from example.com (example.com [127.0.0.1]) by example.com "
            "(Postfix) with ESMTPSA id E8DB612009F for <alice@example.com>; Mon,  6 "
            "Jan 2020 18:01:10 +0200 (CEST)\nMessage-ID: <123456789.123456.123456789."
            "ABCDEF@example.com>\nSubject: Test\nFrom: charlie@example.com\nTo: "
            "alice@example.com\nDate: Mon,  6 Jan 2020 18:01:10 +0200\nContent-Type: "
            'multipart/alternative; boundary="=-pCGCiOTgoFTJJwVyvskX"\nMIME-Version: '
            '1.0\n--=-pCGCiOTgoFTJJwVyvskX\nContent-Type: text/plain; charset="UTF-8"'
            "\nContent-Transfer-Encoding: quoted-printable\nThis is a message, with "
            "some text.\nZ p=C5=9Bija=C5=9Belnym p=C3=B3strowom\nMit freundlichen "
            "Gr=C3=BC=C3=9Fen\ngpgmail\n--=-pCGCiOTgoFTJJwVyvskX\nContent-Type: "
            'text/html; charset="utf-8"\nContent-Transfer-Encoding: quoted-printable'
            "\n<html><head></head><body><div>This is a <b>message</b>, with some "
            "<i>text</=\ni>.</div><div><br></div><div>Z p=C5=9Bija=C5=9Belnym "
            "p=C3=B3strowom</div><d=\niv>Mit freundlichen Gr=C3=BC=C3=9Fen</div><div>"
            "<br></div><div>gpgmail</div>=\n<div><span></span></div></body></html>\n"
            "--=-pCGCiOTgoFTJJwVyvskX--\n--=-spsfm35OzlCD03QPN9Hr--"
        )
        msg = (
            "This is a message, with some text.\nZ p=C5=9Bija=C5=9Belnym p=C3=B3strowom"
            "\nMit freundlichen Gr=C3=BC=C3=9Fen\ngpgmail"
        )
        msg2 = (
            "<html><head></head><body><div>This is a <b>message</b>, with some <i>text"
            "</=\ni>.</div><div><br></div><div>Z p=C5=9Bija=C5=9Belnym p=C3=B3strowom"
            "</div><d=\niv>Mit freundlichen Gr=C3=BC=C3=9Fen</div><div><br></div>"
            "<div>gpgmail</div>=\n<div><span></span></div></body></html>"
        )
        msg3 = "Forwarded Message"

        p = Popen(
            [
                "./gpgmail",
                "-E",
                "-H",
                "alice@example.com",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-p",
                "test",
                "-k",
                self.key_id,
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted, stdout = p.communicate(input=mail)
        self.assertNotIn(msg, encrypted)
        self.assertNotIn(msg2, encrypted)
        self.assertNotIn(msg3, encrypted)
        self.assertIn("", stdout)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                encrypted,
            )
        )

        p = Popen(
            [
                "./gpgmail",
                "-p",
                "test",
                "-k",
                self.key_id,
                "-d",
                "--gnupghome",
                self.temp_gpg_homedir.name,
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        decrypted, stdout = p.communicate(input=encrypted)
        self.assertIn(msg, decrypted)
        self.assertIn(msg2, decrypted)
        self.assertIn(msg3, decrypted)
        self.assertIn("", stdout)

        regex = (
            r'Content-Type:\s+multipart/signed;\s+micalg="pgp-sha512";\s+protocol="appl'
            r'ication/pgp-signature";\s+boundary="=+\d+==".+?--=+\d+==\nContent-Type:'
            r'\s+multipart/mixed;\s+protected-headers="v1";\s+boundary="=+\d+==".+?--=+'
            r'\d+==\nContent-Type:\s+text/rfc822-headers;\s+protected-headers="v1"\nCon'
            r"tent-Disposition: inline\n(Subject:.+?\n|Date:.+?\n|From:.+?\n|Message-ID"
            r":.+?\n|To:.+?\n)+\n\n--=+\d+==\nContent-Type:\s+multipart/mixed;\s+bounda"
            r'ry="=-[\d\w]+"\n\n--=-[\d\w]+\nContent-Type: text/plain\nContent-Transfer'
            r"-Encoding: 7bit\n\nForwarded Message\n--=-[\w\d]+\nContent-Disposition: i"
            r"nline\nContent-Description: Weitergeleitete Nachricht =\?UTF-8\?Q\?=E2=80"
            r"=93\?= Test\nContent-Type: message/rfc822\n.+?Content-Type:\s+multipart/a"
            r'lternative;\s+boundary="=-\w+".+?--=-\w+\nContent-Type: text/plain; chars'
            r'et="UTF-8"\nContent-Transfer-Encoding: quoted-printable\nThis is a messag'
            r"e, with some text\.\nZ p=C5=9Bija=C5=9Belnym p=C3=B3strowom\nMit freundli"
            r"chen Gr=C3=BC=C3=9Fen\ngpgmail\n--=-\w+\nContent-Type: text/html; charset"
            r'="utf-8"\nContent-Transfer-Encoding: quoted-printable\n<html><head></head'
            r"><body><div>This is a <b>message</b>, with some <i>text</=\ni>\.</div><di"
            r"v><br></div><div>Z p=C5=9Bija=C5=9Belnym p=C3=B3strowom</div><d=\niv>Mit "
            r"freundlichen Gr=C3=BC=C3=9Fen</div><div><br></div><div>gpgmail</div>=\n<d"
            r"iv><span></span></div></body></html>\n--=-\w+--\n--=-[\w\d]+--\n\n--=+\d+"
            r'==--\n\n--=+\d+==\nContent-Type: application/pgp-signature; name="signatu'
            r're\.asc"\nContent-Description: OpenPGP digital signature\nContent-Disposi'
            r'tion: attachment; filename="signature\.asc"\n\n-+BEGIN PGP SIGNATURE-+[\w'
            r"\d\+\n=/]+-+END PGP SIGNATURE-+\n\n--=+\d+==--\n"
        )
        self.assertIsNotNone(re.fullmatch(regex, decrypted, flags=re.S))

        mail = (
            "Return-Path: <alice@example.com>\nDelivered-To: bob@example.com\nMIME-"
            "Version: 1.0\nReply-To: alice@example.com\nMessage-ID: <1234567890@examp"
            "le.com>\nDate: Thu, 16 Jun 2022 13:00:00 +0000\nFrom: alice@example.com"
            '\nTo: bob@example.com\nContent-Type: multipart/mixed; boundary="00000000'
            '000093d7be05d23e3c8d"\nSubject: Invitation: Meeting @ Thu Jun 16, 2022 '
            "15:00\n - 16:00 (CET) (bob@example.com)\n\n--00000000000093d7be05d23e3c8"
            'd\nContent-Type: multipart/alternative; boundary="00000000000093d7bc05d2'
            '3e3c8b"\n\n--00000000000093d7bc05d23e3c8b\nContent-Type: text/plain; cha'
            'rset="UTF-8"; format=flowed; delsp=yes\nContent-Transfer-Encoding: base6'
            "4\n\nWW91IGhhdmUgYmVlbiBpbnZpdGVkIHRvIHRoZSBmb2xsb3dpbmcgZXZlbnQuCgpUaXR"
            "sZTogTWVl\ndGluZwpXaGVuOiBUaHUgSnVuIDE2LCAyMDIyIDE1OjAwIOKAkyAxNjowMCBDZ"
            "W50cmFsIEV1cm9w\nZWFuIFRpbWUgLSBCZXJsaW4KCkpvaW5pbmcgaW5mbzogSm9pbiB3aXR"
            "oIEdvb2dsZSBNZWV0Cmh0\ndHBzOi8vZXhhbXBsZS5jb20KCkNhbGVuZGFyOiBib2JAZXhhb"
            "XBsZS5jb20KV2hvOgogICAgICog\nYWxpY2VAZXhhbXBsZS5jb20gLSBvcmdhbml6ZXIKICA"
            "gICAqIGJvYkBleGFtcGxlLmNvbQoKRXZl\nbnQgZGV0YWlsczogIApodHRwczovL2V4YW1wb"
            "GUuY29tCgpJbnZpdGF0aW9uIGZyb20gR29vZ2xl\nIENhbGVuZGFyOiBodHRwczovL2V4YW1"
            "wbGUuY29tCgpZb3UgYXJlIHJlY2VpdmluZyB0aGlzIGNv\ndXJ0ZXN5IGVtYWlsIGF0IHRoZ"
            "SBhY2NvdW50CmJvYkBleGFtcGxlLmNvbSBiZWNhdXNlIHlvdSBh\ncmUgYW4gYXR0ZW5kZWU"
            "gb2YgdGhpcyAgCmV2ZW50LgoKVG8gc3RvcCByZWNlaXZpbmcgZnV0dXJl\nIHVwZGF0ZXMgZ"
            "m9yIHRoaXMgZXZlbnQsIGRlY2xpbmUgdGhpcyBldmVudC4gIApBbHRlcm5hdGl2\nZWx5IHl"
            "vdSBjYW4gc2lnbiB1cCBmb3IgYSBHb29nbGUgYWNjb3VudCBhdCAgCmh0dHBzOi8vZXhh\nb"
            "XBsZS5jb20gYW5kIGNvbnRyb2wgeW91ciBub3RpZmljYXRpb24gIApzZXR0aW5ncyBmb3Ige"
            "W91\nciBlbnRpcmUgY2FsZW5kYXIuCgpGb3J3YXJkaW5nIHRoaXMgaW52aXRhdGlvbiBjb3V"
            "sZCBhbGxv\ndyBhbnkgcmVjaXBpZW50IHRvIHNlbmQgYSByZXNwb25zZSB0byAgCnRoZSBvc"
            "mdhbml6ZXIgYW5k\nIGJlIGFkZGVkIHRvIHRoZSBndWVzdCBsaXN0LCBvciBpbnZpdGUgb3R"
            "oZXJzIHJlZ2FyZGxlc3Mg\nIApvZiB0aGVpciBvd24gaW52aXRhdGlvbiBzdGF0dXMsIG9yI"
            "HRvIG1vZGlmeSB5b3VyIFJTVlAu\nIExlYXJuIG1vcmUgYXQgIApodHRwczovL2V4YW1wbGU"
            'uY29\n--00000000000093d7bc05d23e3c8b\nContent-Type: text/html; charset="'
            'UTF-8"\nContent-Transfer-Encoding: quoted-printable\n\n\n<span itemscope'
            ' itemtype=3D"http://schema.org/InformAction"><span style=3D"=\ndisplay:n'
            'one" itemprop=3D"about" itemscope itemtype=3D"http://schema.org/Pe=\nrso'
            'n"><meta itemprop=3D"description" content=3D"Invitation from alice@examp'
            '=\nle.com"/></span><span itemprop=3D"object" itemscope itemtype=3D"http:'
            '//sche=\nma.org/Event"><div style=3D""><table cellspacing=3D"0" cellpadd'
            'ing=3D"8" bo=\nrder=3D"0" summary=3D"" style=3D"width:100%;font-family:A'
            "rial,Sans-serif;bo=\nrder:1px Solid #ccc;border-width:1px 2px 2px 1px;ba"
            'ckground-color:#fff;"><t=\nr><td><meta itemprop=3D"eventStatus" content='
            '3D"http://schema.org/EventSche=\nduled"/><h4 style=3D"padding:6px 0;marg'
            "in:0 0 4px 0;font-family:Arial,Sans-=\nserif;font-size:13px;line-height:"
            "1.4;border:1px Solid #fff;background:#fff;=\ncolor:#090;font-weight:norm"
            'al"><strong>You have been invited to the followi=\nng event.</strong></h'
            '4><div style=3D"padding:2px"><span itemprop=3D"publish=\ner" itemscope i'
            'temtype=3D"http://schema.org/Organization"><meta itemprop=3D=\n"name" co'
            'ntent=3D"Google Calendar"/></span><meta itemprop=3D"eventId/google=\nCal'
            'endar" content=3D"AAAAAAAAAAAAAAAAAAAAAAAAAAAA"/><h3 style=3D"padding:0 '
            "=\n0 6px 0;margin:0;font-family:Arial,Sans-serif;font-size:16px;font-wei"
            'ght:bo=\nld;color:#222"><span itemprop=3D"name">Meeting</span></h3><tabl'
            'e style=3D"d=\nisplay:inline-table" cellpadding=3D"0" cellspacing=3D"0" '
            'border=3D"0" summa=\nry=3D"Event details"><tr><td style=3D"padding:0 1em'
            " 10px 0;font-family:Aria=\nl,Sans-serif;font-size:13px;color:#888;white-"
            'space:nowrap;width:90px" valig=\nn=3D"top"><div><i style=3D"font-style:n'
            'ormal">When</i></div></td><td style==\n3D"padding-bottom:10px;font-famil'
            'y:Arial,Sans-serif;font-size:13px;color:#2=\n22" valign=3D"top"><div sty'
            'le=3D"text-indent:-1px"><time itemprop=3D"startD=\nate" datetime=3D"2022'
            '0616T140000Z"></time><time itemprop=3D"endDate" dateti=\nme=3D"20220616T'
            '150000Z"></time>Thu Jun 16, 2022 15:00 =E2=80=93 16:00 <span=\n style=3D"c'
            'olor:#888">Central European Time - Berlin</span></div></td></tr>=\n<tr><td'
            ' style=3D"padding:0 1em 4px 0;font-family:Arial,Sans-serif;font-size=\n:13'
            'px;color:#888;white-space:nowrap;width:90px" valign=3D"top"><div><i styl='
            '\ne=3D"font-style:normal">Joining info</i></div></td><td style=3D"padding-'
            'bot=\ntom:4px;font-family:Arial,Sans-serif;font-size:13px;color:#222" vali'
            'gn=3D"t=\nop"><div style=3D"text-indent:-1px">Join with Google Meet</div><'
            '/td></tr><t=\nr><td style=3D"padding:0 1em 10px 0;font-family:Arial,Sans-s'
            'erif;font-size:=\n13px;color:#888;white-space:nowrap;width:90px"></td><td '
            'style=3D"padding-bo=\nttom:10px;font-family:Arial,Sans-serif;font-size:13p'
            'x;color:#222" valign=3D=\n"top"><div style=3D"text-indent:-1px"><div style'
            '=3D"text-indent:-1px"><span=\n itemprop=3D"potentialaction" itemscope item'
            'type=3D"http://schema.org/JoinA=\nction"><span itemprop=3D"name" content=3'
            'D"example.com"><span itemprop=3D"ta=\nrget" itemscope itemtype=3D"http://s'
            'chema.org/EntryPoint"><span itemprop=3D=\n"url" content=3D"https://example'
            '.com"><span itemprop=3D"httpMethod" content=\n=3D"GET"><a href=3D"https://'
            'example.com" style=3D"color:#20c;white-space:no=\nwrap" target=3D"_blank">'
            "example.com</a></span></span></span></span></span> =\n</div></div></td></t"
            'r><tr><td style=3D"padding:0 1em 10px 0;font-family:Ari=\nal,Sans-serif;fo'
            'nt-size:13px;color:#888;white-space:nowrap;width:90px" vali=\ngn=3D"top"><'
            'div><i style=3D"font-style:normal">Calendar</i></div></td><td s=\ntyle=3D"'
            "padding-bottom:10px;font-family:Arial,Sans-serif;font-size:13px;col=\nor:#"
            '222" valign=3D"top"><div style=3D"text-indent:-1px">bob@example.com</di=\n'
            'v></td></tr><tr><td style=3D"padding:0 1em 10px 0;font-family:Arial,Sans-s'
            'e=\nrif;font-size:13px;color:#888;white-space:nowrap;width:90px" valign=3D'
            '"top"=\n><div><i style=3D"font-style:normal">Who</i></div></td><td style=3'
            'D"padding=\n-bottom:10px;font-family:Arial,Sans-serif;font-size:13px;color'
            ':#222" valign=\n=3D"top"><table cellspacing=3D"0" cellpadding=3D"0"><tr><t'
            'd style=3D"paddin=\ng-right:10px;font-family:Arial,Sans-serif;font-size:13'
            'px;color:#222;width:1=\n0px"><div style=3D"text-indent:-1px"><span style=3'
            'D"font-family:Courier New=\n,monospace">&#x2022;</span></div></td><td styl'
            'e=3D"padding-right:10px;font-=\nfamily:Arial,Sans-serif;font-size:13px;col'
            'or:#222"><div style=3D"text-inden=\nt:-1px"><div><div style=3D"margin:0 0 '
            '0.3em 0"><span itemprop=3D"attendee" =\nitemscope itemtype=3D"http://schem'
            'a.org/Person"><span itemprop=3D"name" cla=\nss=3D"notranslate">alice@examp'
            'le.com</span><meta itemprop=3D"email" content=\n=3D"alice@example.com"/></'
            'span><span itemprop=3D"organizer" itemscope itemt=\nype=3D"http://schema.o'
            'rg/Person"><meta itemprop=3D"name" content=3D"alice@e=\nxample.com"/><meta'
            ' itemprop=3D"email" content=3D"alice@example.com"/></span=\n><span style=3'
            'D"font-size:11px;color:#888"> - organizer</span></div></div><=\n/div></td>'
            '</tr><tr><td style=3D"padding-right:10px;font-family:Arial,Sans-s=\nerif;f'
            'ont-size:13px;color:#222;width:10px"><div style=3D"text-indent:-1px">=\n<s'
            'pan style=3D"font-family:Courier New,monospace">&#x2022;</span></div></td='
            '\n><td style=3D"padding-right:10px;font-family:Arial,Sans-serif;font-size:'
            '13p=\nx;color:#222"><div style=3D"text-indent:-1px"><div><div style=3D"mar'
            'gin:0 0=\n 0.3em 0"><span itemprop=3D"attendee" itemscope itemtype=3D"http'
            '://schema.o=\nrg/Person"><span itemprop=3D"name" class=3D"notranslate">bob'
            '@example.com</s=\npan><meta itemprop=3D"email" content=3D"bob@example.com"'
            "/></span></div></di=\nv></div></td></tr></table></td></tr></table><div sty"
            'le=3D"float:right;font-=\nweight:bold;font-size:13px"> <a href=3D"https://'
            'example.com" style=3D"color=\n:#20c;white-space:nowrap" itemprop=3D"url">m'
            'ore details &raquo;</a><br></di=\nv></div><p style=3D"color:#222;font-size'
            ':13px;margin:0"><span style=3D"colo=\nr:#888">Going (bob@example.com)?&nbs'
            'p;&nbsp;&nbsp;</span><wbr><strong><span=\n itemprop=3D"potentialaction" it'
            'emscope itemtype=3D"http://schema.org/RsvpA=\nction"><meta itemprop=3D"att'
            'endance" content=3D"http://schema.org/RsvpAtten=\ndance/Yes"/><span itempr'
            'op=3D"handler" itemscope itemtype=3D"http://schema.=\norg/HttpActionHandle'
            'r"><link itemprop=3D"method" href=3D"http://schema.org/=\nHttpRequestMetho'
            'd/GET"/><a href=3D"https://example.com" style=3D"color:#20c=\n;white-space'
            ':nowrap" itemprop=3D"url">Yes</a></span></span><span style=3D"m=\nargin:0 '
            '0.4em;font-weight:normal"> - </span><span itemprop=3D"potentialacti=\non" '
            'itemscope itemtype=3D"http://schema.org/RsvpAction"><meta itemprop=3D"a=\n'
            'ttendance" content=3D"http://schema.org/RsvpAttendance/Maybe"/><span itemp'
            'r=\nop=3D"handler" itemscope itemtype=3D"http://schema.org/HttpActionHandl'
            'er"><=\nlink itemprop=3D"method" href=3D"http://schema.org/HttpRequestMeth'
            'od/GET"/>=\n<a href=3D"https://example.com" style=3D"color:#20c;white-spac'
            'e:nowrap" ite=\nmprop=3D"url">Maybe</a></span></span><span style=3D"margin'
            ':0 0.4em;font-wei=\nght:normal"> - </span><span itemprop=3D"potentialactio'
            'n" itemscope itemtype=\n=3D"http://schema.org/RsvpAction"><meta itemprop=3'
            'D"attendance" content=3D"=\nhttp://schema.org/RsvpAttendance/No"/><span it'
            'emprop=3D"handler" itemscope =\nitemtype=3D"http://schema.org/HttpActionHa'
            'ndler"><link itemprop=3D"method" =\nhref=3D"http://schema.org/HttpRequestM'
            'ethod/GET"/><a href=3D"https://exampl=\ne.com" style=3D"color:#20c;white-s'
            'pace:nowrap" itemprop=3D"url">No</a></spa=\nn></span></strong>&nbsp;&nbsp;'
            '&nbsp;&nbsp;<wbr><a href=3D"https://example.c=\nom" style=3D"color:#20c;wh'
            'ite-space:nowrap" itemprop=3D"url">more options &=\nraquo;</a></p></td></t'
            'r><tr><td style=3D"background-color:#f6f6f6;color:#88=\n8;border-top:1px S'
            'olid #ccc;font-family:Arial,Sans-serif;font-size:11px"><p=\n>Invitation fr'
            'om <a href=3D"https://exmpale.com" target=3D"_blank" style=3D=\n"">Google '
            "Calendar</a></p><p>You are receiving this courtesy email at the a=\nccount"
            " bob@example.com because you are an attendee of this event.</p><p>To =\nst"
            "op receiving future updates for this event, decline this event. Alternati="
            "\nvely you can sign up for a Google account at https://calendar.google.com"
            "/ca=\nlendar/ and control your notification settings for your entire calen"
            "dar.</p=\n><p>Forwarding this invitation could allow any recipient to send"
            " a response=\n to the organizer and be added to the guest list, or invite "
            "others regardle=\nss of their own invitation status, or to modify your RSV"
            'P. <a href=3D"https=\n://example.com">Learn More</a>.</p></td></tr></table'
            "></div></span></span>\n--00000000000093d7bc05d23e3c8b\nContent-Type: text/"
            'calendar; charset="UTF-8"; method=REQUEST\n\nBEGIN:VCALENDAR\nPRODID:-//Go'
            "ogle Inc//Google Calendar 70.9054//EN\nVERSION:2.0\nCALSCALE:GREGORIAN\nME"
            "THOD:REQUEST\nBEGIN:VEVENT\nDTSTART:20220616T140000Z\nDTEND:20220616T15000"
            "0Z\nDTSTAMP:20220616T130000Z\nORGANIZER;CN=alice@example.com:mailto:alice@"
            "example.com\nUID:AAAAAAAAAAAAAAAAAAAAAAAAAAAA\nATTENDEE;CUTYPE=INDIVIDUAL;"
            "ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED;RSVP=TRUE\n ;CN=alice@example.com;X"
            "-NUM-GUESTS=0:mailto:alice@example.com\nATTENDEE;CUTYPE=INDIVIDUAL;ROLE=RE"
            "Q-PARTICIPANT;PARTSTAT=NEEDS-ACTION;RSVP=\n TRUE;CN=bob@example.com;X-NUM-"
            "GUESTS=0:mailto:bob@example.com\nX-MICROSOFT-CDO-OWNERAPPTID:-000000000\nC"
            "REATED:20220616T130000Z\nDESCRIPTION:-::~:~::~:~:~:~:~:~:~:~:~:~:~:~:~:~:~"
            ":~:~:~:~:~:~:~:~:~:~:~:~:~\n :~:~:~:~:~:~:~:~::~:~::-\nDo not edit this se"
            "ction of the description.\n\nThis event has a video call.\näöüßłšéźžŕÄÖÜŁ-"
            "::~:~:~:~:~:~:~:~:~:~:~:~:~::~:\n ~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:"
            "~:~:~:~:~:~:~:~:~:~:~:~:~:~:~::~:~:\n :-\nLAST-MODIFIED:20220616T130000Z\n"
            "LOCATION:\nSEQUENCE:0\nSTATUS:CONFIRMED\nSUMMARY:Meeting\nTRANSP:OPAQUE\nE"
            "ND:VEVENT\nEND:VCALENDAR\n\n--00000000000093d7bc05d23e3c8b--\n\n--00000000"
            '000093d7be05d23e3c8d\nContent-Type: application/ics; name="invite.ics"\nCo'
            'ntent-Disposition: attachment; filename="invite.ics"\nContent-Transfer-Enc'
            "oding: base64\n\nQkVHSU46VkNBTEVOREFSClBST0RJRDotLy9Hb29nbGUgSW5jLy9Hb29nb"
            "GUgQ2FsZW5kYXIgNzAu\nOTA1NC8vRU4KVkVSU0lPTjoyLjAKQ0FMU0NBTEU6R1JFR09SSUFOC"
            "k1FVEhPRDpSRVFVRVNUCkJF\nR0lOOlZFVkVOVApEVFNUQVJUOjIwMjIwNjE2VDE0MDAwMFoKR"
            "FRFTkQ6MjAyMjA2MTZUMTUwMDAw\nWgpEVFNUQU1QOjIwMjIwNjE2VDEzMDAwMFoKT1JHQU5JW"
            "kVSO0NOPWFsaWNlQGV4YW1wbGUuY29t\nOm1haWx0bzphbGljZUBleGFtcGxlLmNvbQpVSUQ6Q"
            "UFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB\nQQpBVFRFTkRFRTtDVVRZUEU9SU5ESVZJRFVBT"
            "DtST0xFPVJFUS1QQVJUSUNJUEFOVDtQQVJUU1RB\nVD1BQ0NFUFRFRDtSU1ZQPVRSVUUKIDtDT"
            "j1hbGljZUBleGFtcGxlLmNvbTtYLU5VTS1HVUVTVFM9\nMDptYWlsdG86YWxpY2VAZXhhbXBsZ"
            "S5jb20KQVRURU5ERUU7Q1VUWVBFPUlORElWSURVQUw7Uk9M\nRT1SRVEtUEFSVElDSVBBTlQ7U"
            "EFSVFNUQVQ9TkVFRFMtQUNUSU9OO1JTVlA9CiBUUlVFO0NOPWJv\nYkBleGFtcGxlLmNvbTtYL"
            "U5VTS1HVUVTVFM9MDptYWlsdG86Ym9iQGV4YW1wbGUuY29tClgtTUlD\nUk9TT0ZULUNETy1PV"
            "05FUkFQUFRJRDotMDAwMDAwMDAwCkNSRUFURUQ6MjAyMjA2MTZUMTMwMDAw\nWgpERVNDUklQV"
            "ElPTjotOjp+On46On46fjp+On46fjp+On46fjp+On46fjp+On46fjp+On46fjp+\nOn46fjp+O"
            "n46fjp+On46fjp+On4KIDp+On46fjp+On46fjp+On46On46fjo6LVxuRG8gbm90IGVk\naXQgd"
            "GhpcyBzZWN0aW9uIG9mIHRoZSBkZXNjcmlwdGlvbi5cblxuVAogaGlzIGV2ZW50IGhhcyBh\nI"
            "HZpZGVvIGNhbGwuXG7DpMO2w7zDn8WCxaHDqcW6xb7FlcOEw5bDnMWBLTo6fjp+On46fjp+On4"
            "6\nfjp+On46fjp+On46fjo6fjoKIH46fjp+On46fjp+On46fjp+On46fjp+On46fjp+On46fjp"
            "+On46\nfjp+On46fjp+On46fjp+On46fjp+On46fjp+On46fjo6fjp+OgogOi0KTEFTVC1NT0R"
            "JRklFRDoy\nMDIyMDYxNlQxMzAwMDBaCkxPQ0FUSU9OOgpTRVFVRU5DRTowClNUQVRVUzpDT05"
            "GSVJNRUQKU1VN\nTUFSWTpNZWV0aW5nClRSQU5TUDpPUEFRVUUKRU5EOlZFVkVOVApFTkQ6VkN"
            "BTEVOREFS\n--00000000000093d7be05d23e3c8d--"
        )
        msg = (
            "WW91IGhhdmUgYmVlbiBpbnZpdGVkIHRvIHRoZSBmb2xsb3dpbmcgZXZlbnQuCgpUaXRsZTogTW"
            "Vl\ndGluZwpXaGVuOiBUaHUgSnVuIDE2LCAyMDIyIDE1OjAwIOKAkyAxNjowMCBDZW50cmFsIE"
            "V1cm9w\nZWFuIFRpbWUgLSBCZXJsaW4KCkpvaW5pbmcgaW5mbzogSm9pbiB3aXRoIEdvb2dsZS"
            "BNZWV0Cmh0\ndHBzOi8vZXhhbXBsZS5jb20KCkNhbGVuZGFyOiBib2JAZXhhbXBsZS5jb20KV2"
            "hvOgogICAgICog\nYWxpY2VAZXhhbXBsZS5jb20gLSBvcmdhbml6ZXIKICAgICAqIGJvYkBleG"
            "FtcGxlLmNvbQoKRXZl\nbnQgZGV0YWlsczogIApodHRwczovL2V4YW1wbGUuY29tCgpJbnZpdG"
            "F0aW9uIGZyb20gR29vZ2xl\nIENhbGVuZGFyOiBodHRwczovL2V4YW1wbGUuY29tCgpZb3UgYX"
            "JlIHJlY2VpdmluZyB0aGlzIGNv\ndXJ0ZXN5IGVtYWlsIGF0IHRoZSBhY2NvdW50CmJvYkBleG"
            "FtcGxlLmNvbSBiZWNhdXNlIHlvdSBh\ncmUgYW4gYXR0ZW5kZWUgb2YgdGhpcyAgCmV2ZW50Lg"
            "oKVG8gc3RvcCByZWNlaXZpbmcgZnV0dXJl\nIHVwZGF0ZXMgZm9yIHRoaXMgZXZlbnQsIGRlY2"
            "xpbmUgdGhpcyBldmVudC4gIApBbHRlcm5hdGl2\nZWx5IHlvdSBjYW4gc2lnbiB1cCBmb3IgYS"
            "BHb29nbGUgYWNjb3VudCBhdCAgCmh0dHBzOi8vZXhh\nbXBsZS5jb20gYW5kIGNvbnRyb2wgeW"
            "91ciBub3RpZmljYXRpb24gIApzZXR0aW5ncyBmb3IgeW91\nciBlbnRpcmUgY2FsZW5kYXIuCg"
            "pGb3J3YXJkaW5nIHRoaXMgaW52aXRhdGlvbiBjb3VsZCBhbGxv\ndyBhbnkgcmVjaXBpZW50IH"
            "RvIHNlbmQgYSByZXNwb25zZSB0byAgCnRoZSBvcmdhbml6ZXIgYW5k\nIGJlIGFkZGVkIHRvIH"
            "RoZSBndWVzdCBsaXN0LCBvciBpbnZpdGUgb3RoZXJzIHJlZ2FyZGxlc3Mg\nIApvZiB0aGVpci"
            "Bvd24gaW52aXRhdGlvbiBzdGF0dXMsIG9yIHRvIG1vZGlmeSB5b3VyIFJTVlAu\nIExlYXJuIG"
            "1vcmUgYXQgIApodHRwczovL2V4YW1wbGUuY29"
        )
        msg2 = (
            "BEGIN:VCALENDAR\nPRODID:-//Google Inc//Google Calendar 70.9054//EN\n"
            "VERSION:2.0\nCALSCALE:GREGORIAN\nMETHOD:REQUEST\nBEGIN:VEVENT\nDTSTART:"
            "20220616T140000Z\nDTEND:20220616T150000Z\nDTSTAMP:20220616T130000Z\n"
            "ORGANIZER;CN=alice@example.com:mailto:alice@example.com\nUID:AAAAAAAAAAA"
            "AAAAAAAAAAAAAAAAA\nATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTS"
            "TAT=ACCEPTED;RSVP=TRUE\n ;CN=alice@example.com;X-NUM-GUESTS=0:mailto:ali"
            "ce@example.com\nATTENDEE;CUTYPE=INDIVIDUAL;ROLE=REQ-PARTICIPANT;PARTSTAT"
            "=NEEDS-ACTION;RSVP=\n TRUE;CN=bob@example.com;X-NUM-GUESTS=0:mailto:bob@"
            "example.com\nX-MICROSOFT-CDO-OWNERAPPTID:-000000000\nCREATED:20220616T13"
            "0000Z\nDESCRIPTION:-::~:~::~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~"
            ":~:~:~:~:~\n :~:~:~:~:~:~:~:~::~:~::-\nDo not edit this section of the "
            "description.\n\nThis event has a video call.\näöüßłšéźžŕÄÖÜŁ-::~:~:~:~:~"
            ":~:~:~:~:~:~:~:~::~:\n ~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~:~"
            ":~:~:~:~:~:~:~:~:~:~::~:~:\n :-\nLAST-MODIFIED:20220616T130000Z\nLOCATIO"
            "N:\nSEQUENCE:0\nSTATUS:CONFIRMED\nSUMMARY:Meeting\nTRANSP:OPAQUE\nEND:VE"
            "VENT\nEND:VCALENDAR"
        )

        p = Popen(
            [
                "./gpgmail",
                "-E",
                "-H",
                "alice@example.com",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-p",
                "test",
                "-k",
                self.key_id,
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted, stderr = p.communicate(input=mail)
        self.assertNotIn(msg, encrypted)
        self.assertNotIn(msg2, encrypted)
        self.assertEqual("", stderr)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                encrypted,
            )
        )

        p = Popen(
            [
                "./gpgmail",
                "-k",
                self.key_id,
                "-p",
                "test",
                "-d",
                "--gnupghome",
                self.temp_gpg_homedir.name,
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        decrypted, stderr = p.communicate(input=encrypted)
        self.assertIn(msg, decrypted)
        self.assertIn(msg2, decrypted)
        self.assertEqual("", stderr)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                encrypted,
            )
        )

        regex = (
            r'Content-Type:\s+multipart/signed;\s+micalg="pgp-sha512";\s+protocol="appl'
            r'ication/pgp-signature";\s+boundary="=+\d+==".+?--=+\d+==\nContent-Type: m'
            r'ultipart/mixed; protected-headers="v1"; boundary="=+\d+==".+?--=+\d+==\nC'
            r'ontent-Type: text/rfc822-headers; protected-headers="v1"\nContent-Disposi'
            r"tion: inline\n(From:.+?\n|Subject:.+?\n|Message-ID:.+?\n|To:.+?\n|Reply-T"
            r"o:.+?\n|Date:.+?\n)+\n\n--=+\d+==\nContent-Type: multipart/mixed; boundar"
            r'y="[\d\w]+"\n\n--[\d\w]+\nContent-Type: multipart/alternative; boundary="'
            r'[\d\w]+"\n\n--[\d\w]+\nContent-Type: text/plain; charset="UTF-8"; format='
            r"flowed; delsp=yes\nContent-Transfer-Encoding: base64\n\n[\w\d\n\+]+--[\w"
            r'\d]+\nContent-Type: text/html; charset="UTF-8"\nContent-Transfer-Encoding'
            r': quoted-printable.+?--[\w\d]+\nContent-Type: text/calendar; charset="UTF'
            r'-8"; method=REQUEST.+?--[\d\w]+--\n\n--[\w\d]+\nContent-Type: application'
            r'/ics; name="invite\.ics"\nContent-Disposition: attachment; filename="invi'
            r'te\.ics"\nContent-Transfer-Encoding: base64[\n\w\d\+]+--[\w\d]+--\n\n--=+'
            r'\d+==--\n\n--=+\d+==\nContent-Type: application/pgp-signature; name="sign'
            r'ature\.asc"\nContent-Description: OpenPGP digital signature\nContent-Disp'
            r'osition: attachment; filename="signature\.asc"\n\n-+BEGIN PGP SIGNATURE-+'
            r"[\w\d\n\+/=]+-+END PGP SIGNATURE-+\n\n--=+\d+==--\n"
        )
        self.assertIsNotNone(re.fullmatch(regex, decrypted, flags=re.S))

    def test_plus_email_addresses(self):
        """Test signing, encryption and decryption."""
        gpg = gnupg.GPG(gnupghome=self.temp_gpg_homedir.name)

        mail = (
            "Return-Path: <alicei+test@example.com>\nReceived: from example.com (examp"
            "le.com [127.0.0.1])\n    by example.com (Postfix) with ESMTPSA id E8DB612"
            "009F\n    for <alice+test@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 ("
            'CEST)\nContent-Type: text/plain; charset="utf-8"\n MIME-Version: 1.0\n'
            "Content-Transfer-Encoding: 7bit\nSubject: Test\nFrom: alice@example.com"
            "\nTo: alice+test@example.com\nDate: Tue, 07 Jan 2020 19:30:03 -0000\n"
            "Message-ID:\n <123456789.123456.123456789@example.com>\n\nThis is a "
            "test message."
        )
        msg = "This is a test message."

        p = Popen(
            [
                "./gpgmail",
                "-E",
                "alice+test@example.com",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-k",
                self.key_id,
                "-p",
                "test",
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted, stderr = p.communicate(input=mail)
        self.assertNotIn(msg, encrypted)
        self.assertEqual("", stderr)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                encrypted,
            )
        )

        p = Popen(
            [
                "./gpgmail",
                "-d",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-k",
                self.key_id,
                "-p",
                "test",
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        decrypted, stderr = p.communicate(input=encrypted)
        self.assertIn(msg, decrypted)
        self.assertEqual("", stderr)
        self.assertIsNotNone(
            re.search(
                rf"X-gpgmail: gpgmail v\d+\.\d+\.\d+ on {socket.gethostname()}",
                decrypted,
            )
        )

        m = re.search(
            r"--=+\d+==\n(?P<data>.+?)--=+\d+==--.+?(?P<signature>-+BEGIN PGP "
            r"SIGNATURE-+.+?-+END PGP SIGNATURE-+)",
            decrypted,
            flags=re.S,
        )
        self.assertIsNotNone(m)
        with NamedTemporaryFile("wt") as f:
            f.write(m.group("signature"))

            verified = gpg.verify_data(f.name, m.group("data").encode("utf8"))
            self.assertIsNotNone(verified.status)
            self.assertNotEqual("bad signature", verified.status)

        regex = (
            r'Content-Type:\s+multipart/signed;\s+micalg="pgp-sha512";\s+protocol="appl'
            r'ication/pgp-signature";\s+boundary="=+\d+=="\n.+?\n\n--=+\d+==\nContent-T'
            r'ype:\s+multipart/mixed;\s+protected-headers="v1";\s+boundary="=+\d+=="\n'
            r".+?\n\n--=+\d+==\nContent-Type:\s+text/rfc822-headers;\s+protected-header"
            r's="v1"\nContent-Disposition: inline\n(Date:.+?\n|Message-ID:.+?\n|Subject'
            r":.+?\n|To:.+?\n|From:.+?\n)+\n\n--=+\d+==\nContent-Type: text/plain; char"
            r'set="utf-8".+?This is a test message\.\n--=+\d+==--\n\n--=+\d+==\nContent'
            r'-Type: application/pgp-signature; name="signature\.asc"\nContent-Descript'
            r"ion: OpenPGP digital signature\nContent-Disposition: attachment; filename"
            r'="signature\.asc"\n\n-+BEGIN PGP SIGNATURE-+\n\n[\w\n\+/=]+\n-+END PGP SI'
            r"GNATURE-+\n\n--=+\d+==--\n"
        )
        self.assertIsNotNone(re.fullmatch(regex, decrypted, flags=re.S))


if __name__ == "__main__":
    unittest.main()
