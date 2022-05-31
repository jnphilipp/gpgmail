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


import gnupg
import re
import unittest

from subprocess import Popen, PIPE
from tempfile import TemporaryDirectory


class GPGMailTests(unittest.TestCase):
    def setUp(self):
        self.temp_gpg_homedir = TemporaryDirectory()
        gpg = gnupg.GPG(gnupghome=self.temp_gpg_homedir.name)
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
        )
        self.alice_key = gpg.gen_key(alice_input)
        self.assertIsNotNone(self.alice_key)
        self.assertIsNotNone(self.alice_key.fingerprint)

    def tearDown(self):
        self.temp_gpg_homedir.cleanup()

    def test_encrypt_decrypt(self):
        mail = (
            "Return-Path: <alice@example.com>\nReceived: from example.com (example.com "
            + "[127.0.0.1])\n    by example.com (Postfix) with ESMTPSA id E8DB612009F\n"
            + "    for <alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\n"
            + 'Content-Type: text/plain; charset="utf-8"\nMIME-Version: 1.0\n'
            + "Content-Transfer-Encoding: 7bit\nSubject: Test\nFrom: "
            + "alice@example.com\nTo: alice@example.com\nDate: Tue, 07 Jan 2020 "
            + "19:30:03 -0000\nMessage-ID:\n <123456789.123456.123456789@example.com>"
            + "\n\nThis is a test message."
        )
        msg = "This is a test message."

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
        encrypted = p.communicate(input=mail)[0]
        self.assertTrue(msg not in encrypted)

        p = Popen(
            [
                "./gpgmail",
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
        decrypted = p.communicate(input=encrypted)[0]

        self.assertTrue(msg in decrypted)
        regex = (
            r'Content-Type: multipart/mixed; protected-headers="v1";? boundary="'
            + r'===============\d+=="\nMIME-Version: 1\.0\nReturn-Path: <alice@example'
            + r"\.com>\nReceived: from example\.com \(example.com \[127\.0\.0\.1\]\)\n"
            + r"    by example\.com \(Postfix\) with ESMTPSA id E8DB612009F\n    for "
            + r"<alice@example\.com>; Tue,  7 Jan 2020 19:30:03 \+0200 \(CEST\)\n"
            + r"Subject: Test\nFrom: alice@example\.com\nTo: alice@example\.com\nDate: "
            + r"Tue, 07 Jan 2020 19:30:03 -0000\nMessage-ID: \n <123456789\.123456\."
            + r"123456789@example\.com>\n\n--===============\d+==\nContent-Type: "
            + r'text/rfc822-headers; protected-headers="v1"\nContent-Disposition: '
            + r"inline\n(Date: Tue, 07 Jan 2020 19:30:03 -0000\n|Subject: Test\n|From: "
            + r"alice@example\.com\n|To: alice@example\.com\n|Message-ID: \n <123456789"
            + r"\.123456\.123456789@example\.com>\n)+\n\n--===============\d+==\n"
            + r'Content-Type: text/plain; charset="utf-8"\nContent-Transfer-Encoding: '
            + r"7bit\n\nThis is a test message\.\n--===============\d+==--\n"
        )
        self.assertIsNotNone(re.fullmatch(regex, decrypted))

    def test_sign(self):
        mail = (
            "Return-Path: <alice@example.com>\nReceived: from example.com (example.com "
            + "[127.0.0.1])\n    by example.com (Postfix) with ESMTPSA id E8DB612009F\n"
            + "    for <alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\n"
            + 'Content-Type: text/plain; charset="utf-8"\nMIME-Version: 1.0\n'
            + "Content-Transfer-Encoding: 7bit\nSubject: Test\nFrom: "
            + "alice@example.com\nTo: alice@example.com\nDate: Tue, 07 Jan 2020 "
            + "19:30:03 -0000\nMessage-ID:\n <123456789.123456.123456789@example.com>"
            + "\n\nThis is a test message."
        )
        msg = "This is a test message."

        p = Popen(
            [
                "./gpgmail",
                "-s",
                "alice@example.com",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-p",
                "test",
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        signed = p.communicate(input=mail)[0]

        self.assertTrue(msg in signed)
        regex = (
            r"Content-Type: multipart/signed; micalg=\"pgp-sha512\"; "
            + r"protocol=\"application/pgp-signature\"; "
            + r"boundary=\"===============\d+==\"\nMIME-Version: 1\.0\n"
            + r"Return-Path: <alice@example\.com>\nReceived: from "
            + r"example\.com \(example\.com \[127\.0\.0\.1\]\)\n    by "
            + r"example\.com \(Postfix\) with ESMTPSA id E8DB612009F\n    "
            + r"for <alice@example\.com>; Tue,  7 Jan 2020 19:30:03 \+0200 "
            + r"\(CEST\)\nSubject: Test\nFrom: alice@example\.com\nTo: "
            + r"alice@example\.com\nDate: Tue, 07 Jan 2020 19:30:03 "
            + r"-0000\nMessage-ID: \n <123456789\.123456\.123456789@example"
            + r"\.com>\n\n--===============\d+==\nContent-Type: "
            + r"multipart/mixed; protected-headers=\"v1\"; "
            + r"boundary=\"===============\d+==\"\nMIME-Version: 1\.0\n"
            + r"Return-Path: <alice@example\.com>\nReceived: from "
            + r"example\.com \(example\.com \[127\.0\.0\.1\]\)\n    by "
            + r"example.com \(Postfix\) with ESMTPSA id E8DB612009F\n    for"
            + r" <alice@example\.com>; Tue,  7 Jan 2020 19:30:03 \+0200 "
            + r"\(CEST\)\nSubject: Test\nFrom: alice@example.com\nTo: "
            + r"alice@example\.com\nDate: Tue, 07 Jan 2020 19:30:03 -0000\n"
            + r"Message-ID: \n <123456789\.123456\.123456789@example\.com>\n"
            + r"\n--===============\d+==\nContent-Type: text/rfc822-headers;"
            + r" protected-headers=\"v1\"\nContent-Disposition: inline\n"
            + r"(Date: Tue, 07 Jan 2020 19:30:03 -0000\n|Subject: Test\n|"
            + r"From: alice@example\.com\n|To: alice@example\.com\n|"
            + r"Message-ID: \n <123456789\.123456\.123456789@example\.com>\n"
            + r")+\n\n--===============\d+==\nContent-Type: text/plain; "
            + r"charset=\"utf-8\"\nContent-Transfer-Encoding: 7bit\n\nThis "
            + r"is a test message\.\n--===============\d+==--\n\n"
            + r"--===============\d+==\nContent-Type: application/pgp-"
            + r"signature; name=\"signature\.asc\"\nContent-Description: "
            + r"OpenPGP digital signature\nContent-Disposition: attachment; "
            + r"filename=\"signature\.asc\"\n\n-----BEGIN PGP SIGNATURE-----"
            + r"\n\n[\w\+/\n=]+-----END PGP SIGNATURE-----\n\n"
            + r"--===============\d+==--\n"
        )
        self.assertIsNotNone(re.fullmatch(regex, signed))

    def test_sign_encrypt_decrypt(self):
        mail = (
            "Return-Path: <alice@example.com>\nReceived: from example.com (example.com "
            + "[127.0.0.1])\n    by example.com (Postfix) with ESMTPSA id E8DB612009F\n"
            + "    for <alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\n"
            + 'Content-Type: text/plain; charset="utf-8"\n MIME-Version: 1.0\n'
            + "Content-Transfer-Encoding: 7bit\nSubject: Test\nFrom: alice@example.com"
            + "\nTo: alice@example.com\nDate: Tue, 07 Jan 2020 19:30:03 -0000\n"
            + "Message-ID:\n <123456789.123456.123456789@example.com>\n\nThis is a "
            + "test message."
        )
        msg = "This is a test message."

        p = Popen(
            [
                "./gpgmail",
                "-E",
                "alice@example.com",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-p",
                "test",
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted = p.communicate(input=mail)[0]
        self.assertTrue(msg not in encrypted)

        p = Popen(
            [
                "./gpgmail",
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
        decrypted = p.communicate(input=encrypted)[0]

        self.assertTrue(msg in decrypted)
        regex = (
            r'Content-Type: multipart/mixed; protected-headers="v1"; boundary="'
            + r'===============\d+=="\nMIME-Version: 1\.0\nReturn-Path: <alice@example'
            + r"\.com>\nReceived: from example\.com \(example.com \[127\.0\.0\.1\]\)\n"
            + r"    by example\.com \(Postfix\) with ESMTPSA id E8DB612009F\n    for "
            + r"<alice@example\.com>; Tue,  7 Jan 2020 19:30:03 \+0200 \(CEST\)\n"
            + r"Subject: Test\nFrom: alice@example\.com\nTo: alice@example\.com\nDate: "
            + r"Tue, 07 Jan 2020 19:30:03 -0000\nMessage-ID: \n <123456789\.123456\."
            + r"123456789@example\.com>\n\n--===============\d+==\nContent-Type: text/"
            + r'rfc822-headers; protected-headers="v1"\nContent-Disposition: inline\n'
            + r"(Date: Tue, 07 Jan 2020 19:30:03 -0000\n|Subject: Test\n|From: "
            + r"alice@example\.com\n|To: alice@example\.com\n|Message-ID: \n"
            + r" <123456789\.123456\.123456789@example\.com>\n)+\n\n--==============="
            + r'\d+==\nContent-Type: text/plain; charset="utf-8"\n MIME-Version: 1.0\n'
            + r"Content-Transfer-Encoding: 7bit\n\nThis is a test message\.\n--"
            + r"===============\d+==--\n"
        )
        self.assertIsNotNone(re.fullmatch(regex, decrypted))

    def test_encryptheaders(self):
        mail = (
            "Return-Path: <alice@example.com>\nReceived: from example.com (example.com "
            + "[127.0.0.1])\n    by example.com (Postfix) with ESMTPSA id E8DB612009F\n"
            + "    for <alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\n"
            + 'Content-Type: text/plain; charset="utf-8"\nMIME-Version: 1.0\n'
            + "Content-Transfer-Encoding: 7bit\nSubject: Test\nFrom: alice@example.com"
            + "\nTo: alice@example.com\nDate: Tue, 07 Jan 2020 19:30:03 -0000\n"
            + "Message-ID:\n <123456789.123456.123456789@example.com>\n\nThis is a "
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
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted, stderr = p.communicate(input=mail)
        self.assertTrue(msg not in encrypted)
        self.assertIn("Date: ...\n", encrypted)
        self.assertIn("From: ...\n", encrypted)
        self.assertIn("Message-ID: ...\n", encrypted)
        self.assertIn("Subject: ...\n", encrypted)
        self.assertIn("To: ...\n", encrypted)

    def test_encryptfail(self):
        mail = (
            "Return-Path: <alice@example.com>\nReceived: from example.com (example.com "
            + "[127.0.0.1])\n    by example.com (Postfix) with ESMTPSA id E8DB612009F\n"
            + "    for <alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\n"
            + 'Content-Type: text/plain; charset="utf-8"\nMIME-Version: 1.0\n'
            + "Content-Transfer-Encoding: 7bit\nSubject: Test\nFrom: alice@example.com"
            + "\nTo: alice@example.com\nDate: Tue, 07 Jan 2020 19:30:03 -0000\n"
            + "Message-ID:\n <123456789.123456.123456789@example.com>\n\nThis is a "
            + "test message."
        )

        p = Popen(
            [
                "./gpgmail",
                "-e",
                "alice.do@example.com",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-H",
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted, stderr = p.communicate(input=mail)
        self.assertEqual(mail, encrypted)

        mail = (
            "Return-Path: <alice@example.com>\nReceived: from example.com (example.com "
            + "[127.0.0.1])\n    by example.com (Postfix) with ESMTPSA id E8DB612009F\n"
            + "    for <alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\n"
            + 'Content-Type: text/plain; charset="utf-8"\n MIME-Version: 1.0\n'
            + "Content-Transfer-Encoding: 7bit\nSubject: Test\nFrom: alice@example.com"
            + "\nTo: alice@example.com\nDate: Tue, 07 Jan 2020 19:30:03 -0000\n"
            + "Message-ID:\n <123456789.123456.123456789@example.com>\n\nFür alle "
            + "Räuber in der Röhn, es gibt ein neues Café.\nÄÖÜß\n\nZ pśijaśelnym "
            + "póstrowom\nMit freundlichen Grüßen\ngpgmail"
        )

        p = Popen(
            [
                "./gpgmail",
                "-e",
                "alice.do@example.com",
                "--gnupghome",
                self.temp_gpg_homedir.name,
                "-H",
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted, stderr = p.communicate(input=mail)
        self.assertEqual(mail, encrypted)

    def test_sign_encrypt_decrypt_utf8(self):
        mail = (
            "Return-Path: <alice@example.com>\nReceived: from example.com (example.com "
            + "[127.0.0.1])\n    by example.com (Postfix) with ESMTPSA id E8DB612009F\n"
            + "    for <alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\n"
            + 'Content-Type: text/plain; charset="utf-8"\n MIME-Version: 1.0\n'
            + "Content-Transfer-Encoding: 8bit\nSubject: Test\nFrom: alice@example.com"
            + "\nTo: alice@example.com\nDate: Tue, 07 Jan 2020 19:30:03 -0000\n"
            + "Message-ID:\n <123456789.123456.123456789@example.com>\n\nFür alle "
            + "Räuber in der Röhn, es gibt ein neues Café.\nÄÖÜß\n\nZ pśijaśelnym "
            + "póstrowom\nMit freundlichen Grüßen\ngpgmail"
        )
        msg = (
            "Für alle Räuber in der Röhn, es gibt ein neues Café.\nÄÖÜß\n\n"
            + "Z pśijaśelnym póstrowom\nMit freundlichen Grüßen\ngpgmail"
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
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted = p.communicate(input=mail)[0]
        self.assertTrue(msg not in encrypted)

        p = Popen(
            [
                "./gpgmail",
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
        decrypted = p.communicate(input=encrypted)[0]

        self.assertTrue(msg in decrypted)
        regex = (
            r'Content-Type: multipart/mixed; protected-headers="v1"; boundary="'
            + r'===============\d+=="\nMIME-Version: 1\.0\nReturn-Path: <alice@example'
            + r"\.com>\nReceived: from example\.com \(example.com \[127\.0\.0\.1\]\)\n"
            + r"    by example\.com \(Postfix\) with ESMTPSA id E8DB612009F\n    for "
            + r"<alice@example\.com>; Tue,  7 Jan 2020 19:30:03 \+0200 \(CEST\)\n"
            + r"Subject: Test\nFrom: alice@example\.com\nTo: alice@example\.com\nDate: "
            + r"Tue, 07 Jan 2020 19:30:03 -0000\nMessage-ID: \n <123456789\.123456\."
            + r"123456789@example\.com>\n\n--===============\d+==\nContent-Type: text/"
            + r'rfc822-headers; protected-headers="v1"\nContent-Disposition: inline\n'
            + r"(Date: Tue, 07 Jan 2020 19:30:03 -0000\n|Subject: Test\n|From: "
            + r"alice@example\.com\n|To: alice@example\.com\n|Message-ID: \n"
            + r" <123456789\.123456\.123456789@example\.com>\n)+\n\n--==============="
            + r'\d+==\nContent-Type: text/plain; charset="utf-8"\n MIME-Version: 1.0\n'
            + r"Content-Transfer-Encoding: 7bit\n\nFür alle Räuber in der Röhn, es gibt"
            + r" ein neues Café\.\nÄÖÜß\n\nZ pśijaśelnym póstrowom\nMit freundlichen "
            + r"Grüßen\ngpgmail\n--===============\d+==--\n"
        )
        self.assertIsNotNone(re.fullmatch(regex, decrypted))

    def test_multipart_message(self):
        mail = (
            "Return-Path: <alice@example.com>\nReceived: from example.com (example.com "
            + "[127.0.0.1]) by example.com (Postfix) with ESMTPSA id E8DB612009F for "
            + "<alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\nMessage-ID:"
            + " <123456789.123456.123456789@example.com>\nSubject: Test\nFrom: "
            + "alice@example.com\nTo: alice@example.com\nDate: Tue, 07 Jan 2020 "
            + "19:30:03 -0000\nContent-Type: multipart/alternative;\n"
            + 'boundary="=-pCGCiOTgoFTJJwVyvskX"\nMIME-Version: 1.0\n\n'
            + '--=-pCGCiOTgoFTJJwVyvskX\nContent-Type: text/plain; charset="UTF-8"\n'
            + "Content-Transfer-Encoding: 8bit\n\nThis is a message, with some text."
            + "\n\nZ pśijaśelnym póstrowom\nMit freundlichen Grüßen\n\ngpgmail\n\n"
            + '--=-pCGCiOTgoFTJJwVyvskX\nContent-Type: text/html; charset="utf-8"\n'
            + "Content-Transfer-Encoding: 8bit\n\n<html><head></head><body><div>"
            + "This is a <b>message</b>, with some <i>text</=\ni>.</div><div><br></div>"
            + "<div>Z pśijaśelnym póstrowom</div><d=\niv>Mit freundlichen Grüßen</div>"
            + "<div><br></div><div>gpgmail</div>=\n<div><span></span></div></body>"
            + "</html>\n\n--=-pCGCiOTgoFTJJwVyvskX--"
        )
        msg = (
            "This is a message, with some text.\n\nZ pśijaśelnym póstrowom\n"
            + "Mit freundlichen Grüßen\n\ngpgmail"
        )
        msg2 = (
            "<html><head></head><body><div>This is a <b>message</b>, with some <i>text"
            + "</=\ni>.</div><div><br></div><div>Z pśijaśelnym póstrowom</div><d=\niv>"
            + "Mit freundlichen Grüßen</div><div><br></div><div>gpgmail</div>=\n<div>"
            + "<span></span></div></body></html>"
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
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted = p.communicate(input=mail)[0]
        self.assertTrue(msg not in encrypted)
        self.assertTrue(msg2 not in encrypted)

        p = Popen(
            [
                "./gpgmail",
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
        decrypted = p.communicate(input=encrypted)[0]

        self.assertTrue(msg in decrypted)
        self.assertTrue(msg2 in decrypted)
        regex = (
            r'Content-Type: multipart/mixed; protected-headers="v1"; '
            + r'boundary="===============\d+=="\nMIME-Version: 1\.0\nReturn-Path: '
            + r"<alice@example\.com>\nReceived: from example\.com \(example\.com "
            + r"\[127\.0\.0\.1\]\) by example\.com \(Postfix\) with ESMTPSA id "
            + r"E8DB612009F for <alice@example\.com>; Tue,  7 Jan 2020 19:30:03 \+0200 "
            + r"\(CEST\)\nMessage-ID: <123456789\.123456\.123456789@example\.com>\n"
            + r"Subject: Test\nFrom: alice@example\.com\nTo: alice@example\.com\nDate: "
            + r"Tue, 07 Jan 2020 19:30:03 -0000\n\n--===============\d+==\n"
            + r'Content-Type: text/rfc822-headers; protected-headers="v1"\n'
            + r"(Content-Disposition: inline\n|Date: Tue, 07 Jan 2020 19:30:03 -0000\n|"
            + r"From: alice@example\.com\n|Subject: Test\n|To: alice@example\.com\n|"
            + r"Message-ID: <123456789\.123456\.123456789@example\.com>\n)+\n\n"
            + r"--===============\d+==\nContent-Type: multipart/alternative;\n\n"
            + r'boundary="=-pCGCiOTgoFTJJwVyvskX"\nMIME-Version: 1\.0\n\n'
            + r'--=-pCGCiOTgoFTJJwVyvskX\nContent-Type: text/plain; charset="UTF-8"\n'
            + r"Content-Transfer-Encoding: 8bit\n\nThis is a message, with some text\."
            + r"\n\nZ pśijaśelnym póstrowom\nMit freundlichen Grüßen\n\ngpgmail\n\n"
            + r'--=-pCGCiOTgoFTJJwVyvskX\nContent-Type: text/html; charset="utf-8"\n'
            + r"Content-Transfer-Encoding: 8bit\n\n<html><head></head><body><div>"
            + r"This is a <b>message</b>, with some <i>text</=\ni>\.</div><div><br>"
            + r"</div><div>Z pśijaśelnym póstrowom</div><d=\niv>Mit freundlichen Grüßen"
            + r"</div><div><br></div><div>gpgmail</div>=\n<div><span></span></div>"
            + r"</body></html>\n\n--=-pCGCiOTgoFTJJwVyvskX--\n--===============\d+==--"
            + r"\n"
        )
        self.assertIsNotNone(re.fullmatch(regex, decrypted))

        mail = (
            "Return-Path: <bob@example.com>\nX-Original-To: alice@example.com\n"
            + "Delivered-To: alice@example.com\nReceived: from example.com (example.com"
            + " [127.0.0.1]) by example.com (Postfix) with ESMTPSA id E8DB612009F for "
            + "<alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 (CEST)\nMessage-ID:"
            + " <123456789.123456.123456789@example.com>\nFrom: bob@example.com\nTo: "
            + "alice@example.com\nDate: Tue,  7 Jan 2020 19:30:03 +0200\nReferences: "
            + "<123456789.123456.123456789.ABCDEF@example.com>\nContent-Type: "
            + 'multipart/mixed; boundary="=-spsfm35OzlCD03QPN9Hr"\nMIME-Version: 1.0\n'
            + "Subject: Fwd: Test\n--=-spsfm35OzlCD03QPN9Hr\nContent-Type: text/plain\n"
            + "Content-Transfer-Encoding: 7bit\nForwarded Message\n"
            + "--=-spsfm35OzlCD03QPN9Hr\nContent-Disposition: inline\n"
            + "Content-Description: Weitergeleitete Nachricht =?UTF-8?Q?=E2=80=93?= "
            + "Test\nContent-Type: message/rfc822\nReturn-Path: <charlie@example.com>\n"
            + "Received: from example.com (example.com [127.0.0.1]) by example.com "
            + "(Postfix) with ESMTPSA id E8DB612009F for <alice@example.com>; Mon,  6 "
            + "Jan 2020 18:01:10 +0200 (CEST)\nMessage-ID: <123456789.123456.123456789."
            + "ABCDEF@example.com>\nSubject: Test\nFrom: charlie@example.com\nTo: "
            + "alice@example.com\nDate: Mon,  6 Jan 2020 18:01:10 +0200\nContent-Type: "
            + 'multipart/alternative; boundary="=-pCGCiOTgoFTJJwVyvskX"\nMIME-Version: '
            + '1.0\n--=-pCGCiOTgoFTJJwVyvskX\nContent-Type: text/plain; charset="UTF-8"'
            + "\nContent-Transfer-Encoding: quoted-printable\nThis is a message, with "
            + "some text.\nZ p=C5=9Bija=C5=9Belnym p=C3=B3strowom\nMit freundlichen "
            + "Gr=C3=BC=C3=9Fen\ngpgmail\n--=-pCGCiOTgoFTJJwVyvskX\nContent-Type: "
            + 'text/html; charset="utf-8"\nContent-Transfer-Encoding: quoted-printable'
            + "\n<html><head></head><body><div>This is a <b>message</b>, with some "
            + "<i>text</=\ni>.</div><div><br></div><div>Z p=C5=9Bija=C5=9Belnym "
            + "p=C3=B3strowom</div><d=\niv>Mit freundlichen Gr=C3=BC=C3=9Fen</div><div>"
            + "<br></div><div>gpgmail</div>=\n<div><span></span></div></body></html>\n"
            + "--=-pCGCiOTgoFTJJwVyvskX--\n--=-spsfm35OzlCD03QPN9Hr--"
        )
        msg = (
            "This is a message, with some text.\nZ p=C5=9Bija=C5=9Belnym p=C3=B3strowom"
            + "\nMit freundlichen Gr=C3=BC=C3=9Fen\ngpgmail"
        )
        msg2 = (
            "<html><head></head><body><div>This is a <b>message</b>, with some <i>text"
            + "</=\ni>.</div><div><br></div><div>Z p=C5=9Bija=C5=9Belnym p=C3=B3strowom"
            + "</div><d=\niv>Mit freundlichen Gr=C3=BC=C3=9Fen</div><div><br></div>"
            + "<div>gpgmail</div>=\n<div><span></span></div></body></html>"
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
            ],
            stdout=PIPE,
            stdin=PIPE,
            stderr=PIPE,
            encoding="utf8",
        )
        encrypted = p.communicate(input=mail)[0]
        self.assertTrue(msg not in encrypted)
        self.assertTrue(msg2 not in encrypted)
        self.assertTrue(msg3 not in encrypted)

        p = Popen(
            [
                "./gpgmail",
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
        decrypted = p.communicate(input=encrypted)[0]

        self.assertTrue(msg in decrypted)
        self.assertTrue(msg2 in decrypted)
        self.assertTrue(msg3 in decrypted)
        regex = (
            r'Content-Type: multipart/mixed; protected-headers="v1"; '
            + r'boundary="===============\d+=="\nMIME-Version: 1\.0\nReturn-Path: '
            + r"<bob@example\.com>\nX-Original-To: alice@example\.com\nDelivered-To: "
            + r"alice@example\.com\nReceived: from example\.com \(example\.com "
            + r"\[127\.0\.0\.1\]\) by example\.com \(Postfix\) with ESMTPSA id "
            + r"E8DB612009F for <alice@example\.com>; Tue,  7 Jan 2020 19:30:03 \+0200 "
            + r"\(CEST\)\nMessage-ID: <123456789\.123456\.123456789@example\.com>\n"
            + r"From: bob@example\.com\nTo: alice@example\.com\nDate: Tue,  7 Jan 2020 "
            + r"19:30:03 \+0200\nReferences: <123456789\.123456\.123456789\.ABCDEF@"
            + r"example\.com>\nSubject: Fwd: Test\n\n--===============\d+==\n"
            + r'Content-Type: text/rfc822-headers; protected-headers="v1"\n'
            + r"Content-Disposition: inline\n(Message-ID: <123456789\.123456\.123456789"
            + r"@example\.com>\n|From: bob@example\.com\n|Subject: Fwd: Test\n|Date: "
            + r"Tue,  7 Jan 2020 19:30:03 \+0200\n|References: <123456789\.123456\."
            + r"123456789\.ABCDEF@example\.com>\n|To: alice@example\.com\n)+\n\n"
            + r"--===============\d+==\nContent-Type: multipart/mixed; "
            + r'boundary="=-spsfm35OzlCD03QPN9Hr"\n\n--=-spsfm35OzlCD03QPN9Hr\n'
            + r"Content-Type: text/plain\nContent-Transfer-Encoding: 7bit\n\n"
            + r"Forwarded Message\n--=-spsfm35OzlCD03QPN9Hr\nContent-Disposition: "
            + r"inline\nContent-Description: Weitergeleitete Nachricht "
            + r"=\?UTF-8\?Q\?=E2=80=93\?= Test\nContent-Type: message/rfc822\n"
            + r"Return-Path: <charlie@example\.com>\nReceived: from example\.com "
            + r"\(example\.com \[127\.0\.0\.1\]\) by example\.com \(Postfix\) with "
            + r"ESMTPSA id E8DB612009F for <alice@example\.com>; Mon,  6 Jan 2020 "
            + r"18:01:10 \+0200 \(CEST\)\nMessage-ID: <123456789\.123456\.123456789\."
            + r"ABCDEF@example\.com>\nSubject: Test\nFrom: charlie@example\.com\nTo: "
            + r"alice@example\.com\nDate: Mon,  6 Jan 2020 18:01:10 \+0200\n"
            + r'Content-Type: multipart/alternative; boundary="=-pCGCiOTgoFTJJwVyvskX"'
            + r"\nMIME-Version: 1\.0\n\n\n--=-pCGCiOTgoFTJJwVyvskX\nContent-Type: "
            + r'text/plain; charset="UTF-8"\nContent-Transfer-Encoding: '
            + r"quoted-printable\nThis is a message, with some text\.\nZ "
            + r"p=C5=9Bija=C5=9Belnym p=C3=B3strowom\nMit freundlichen Gr=C3=BC=C3=9Fen"
            + r"\ngpgmail\n--=-pCGCiOTgoFTJJwVyvskX\nContent-Type: text/html; "
            + r'charset="utf-8"\nContent-Transfer-Encoding: quoted-printable\n<html>'
            + r"<head></head><body><div>This is a <b>message</b>, with some <i>text</="
            + r"\ni>\.</div><div><br></div><div>Z p=C5=9Bija=C5=9Belnym p=C3=B3strowom"
            + r"</div><d=\niv>Mit freundlichen Gr=C3=BC=C3=9Fen</div><div><br></div>"
            + r"<div>gpgmail</div>=\n<div><span></span></div></body></html>\n"
            + r"--=-pCGCiOTgoFTJJwVyvskX--\n--=-spsfm35OzlCD03QPN9Hr--\n\n"
            + r"--===============\d+==--\n"
        )
        self.assertIsNotNone(re.fullmatch(regex, decrypted))


if __name__ == "__main__":
    unittest.main()
