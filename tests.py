#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright (C) 2019-2020 J. Nathanael Philipp (jnphilipp)
# <nathanael@philipp.land>
"""
This file is part of gpgmail.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
"""


import gnupg
import re
import unittest

from subprocess import Popen, PIPE, STDOUT
from tempfile import TemporaryDirectory


class GPGMailTests(unittest.TestCase):
    def setUp(self):
        self.temp_gpg_homedir = TemporaryDirectory()
        gpg = gnupg.GPG(gnupghome=self.temp_gpg_homedir.name)
        alice_input = gpg.gen_key_input(name_real='Alice',
                                        name_email='alice@example.com',
                                        key_type='RSA', key_length=4096,
                                        key_usage='', subkey_type='RSA',
                                        subkey_length=4096, passphrase='test',
                                        subkey_usage='encrypt,sign,auth')
        self.alice_key = gpg.gen_key(alice_input)
        self.assertIsNotNone(self.alice_key)
        self.assertIsNotNone(self.alice_key.fingerprint)

    def tearDown(self):
        self.temp_gpg_homedir.cleanup()

    def test_encrypt_decrypt(self):
        mail = 'Return-Path: <alice@example.com>\nReceived: from ' + \
            'example.com (example.com [127.0.0.1])\n    by example.com ' + \
            '(Postfix) with ESMTPSA id E8DB612009F\n    for ' + \
            '<alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 ' + \
            '(CEST)\nContent-Type: text/plain; charset="utf-8"\n' + \
            'MIME-Version: 1.0\nContent-Transfer-Encoding: 7bit\n' + \
            'Subject: Test\nFrom: alice@example.com\n' + \
            'To: alice@example.com\nDate: Tue, 07 Jan 2020 19:30:03 ' + \
            '-0000\nMessage-ID:\n ' + \
            '<123456789.123456.123456789@example.com>\n\nThis is a test ' + \
            'message.'
        msg = 'This is a test message.'

        p = Popen(['./gpgmail', '-e', 'alice@example.com', '--gnupghome',
                   self.temp_gpg_homedir.name], stdout=PIPE, stdin=PIPE,
                  stderr=PIPE, encoding='utf8')
        encrypted = p.communicate(input=mail)[0]
        self.assertTrue(msg not in encrypted)

        p = Popen(['./gpgmail', '-p', 'test', '-d', '--gnupghome',
                   self.temp_gpg_homedir.name], stdout=PIPE, stdin=PIPE,
                  stderr=PIPE, encoding='utf8')
        decrypted = p.communicate(input=encrypted)[0]

        self.assertTrue(msg in decrypted)
        regex = r'Content-Type: multipart/mixed; protected-headers="v1";? ' + \
            r'boundary="===============\d+=="\nMIME-Version: 1\.0\n' + \
            r'Return-Path: <alice@example\.com>\nReceived: from ' + \
            r'example\.com \(example.com \[127\.0\.0\.1\]\)\n    by ' + \
            r'example\.com \(Postfix\) with ESMTPSA id E8DB612009F\n    ' + \
            r'for <alice@example\.com>; Tue,  7 Jan 2020 19:30:03 \+0200 ' + \
            r'\(CEST\)\nSubject: Test\nFrom: alice@example\.com\nTo: ' + \
            r'alice@example\.com\nDate: Tue, 07 Jan 2020 19:30:03 -0000\n' + \
            r'Message-ID: \n <123456789\.123456\.123456789@example\.com>\n' + \
            r'\n--===============\d+==\nContent-Type: text/rfc822-headers;' + \
            r' protected-headers="v1"\nContent-Disposition: inline\n(Date:' + \
            r' Tue, 07 Jan 2020 19:30:03 -0000\n|Subject: Test\n|From: ' + \
            r'alice@example\.com\n|To: alice@example\.com\n|Message-ID: \n' + \
            r' <123456789\.123456\.123456789@example\.com>\n)+\n\n' + \
            r'--===============\d+==\nContent-Type: text/plain; ' + \
            r'charset="utf-8"\nContent-Transfer-Encoding: 7bit\n\nThis is ' + \
            r'a test message\.\n--===============\d+==--\n'
        self.assertIsNotNone(re.fullmatch(regex, decrypted))

    def test_sign(self):
        mail = 'Return-Path: <alice@example.com>\nReceived: from ' + \
            'example.com (example.com [127.0.0.1])\n    by example.com ' + \
            '(Postfix) with ESMTPSA id E8DB612009F\n    for ' + \
            '<alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 ' + \
            '(CEST)\nContent-Type: text/plain; charset="utf-8"\n' + \
            'MIME-Version: 1.0\nContent-Transfer-Encoding: 7bit\n' + \
            'Subject: Test\nFrom: alice@example.com\n' + \
            'To: alice@example.com\nDate: Tue, 07 Jan 2020 19:30:03 ' + \
            '-0000\nMessage-ID:\n ' + \
            '<123456789.123456.123456789@example.com>\n\nThis is a test ' + \
            'message.'
        msg = 'This is a test message.'

        p = Popen(['./gpgmail', '-s', 'alice@example.com', '--gnupghome',
                   self.temp_gpg_homedir.name, '-p', 'test'], stdout=PIPE,
                  stdin=PIPE, stderr=PIPE, encoding='utf8')
        signed = p.communicate(input=mail)[0]

        self.assertTrue(msg in signed)
        regex = r'Content-Type: multipart/signed; micalg=\"pgp-sha512\"; ' + \
            r'protocol=\"application/pgp-signature\"; ' + \
            r'boundary=\"===============\d+==\"\nMIME-Version: 1\.0\n' + \
            r'Return-Path: <alice@example\.com>\nReceived: from ' + \
            r'example\.com \(example\.com \[127\.0\.0\.1\]\)\n    by ' + \
            r'example\.com \(Postfix\) with ESMTPSA id E8DB612009F\n    ' + \
            r'for <alice@example\.com>; Tue,  7 Jan 2020 19:30:03 \+0200 ' + \
            r'\(CEST\)\nSubject: Test\nFrom: alice@example\.com\nTo: ' + \
            r'alice@example\.com\nDate: Tue, 07 Jan 2020 19:30:03 ' + \
            r'-0000\nMessage-ID: \n <123456789\.123456\.123456789@example' + \
            r'\.com>\n\n--===============\d+==\nContent-Type: ' + \
            r'multipart/mixed; protected-headers=\"v1\"; ' + \
            r'boundary=\"===============\d+==\"\nMIME-Version: 1\.0\n' + \
            r'Return-Path: <alice@example\.com>\nReceived: from ' + \
            r'example\.com \(example\.com \[127\.0\.0\.1\]\)\n    by ' + \
            r'example.com \(Postfix\) with ESMTPSA id E8DB612009F\n    for' + \
            r' <alice@example\.com>; Tue,  7 Jan 2020 19:30:03 \+0200 ' + \
            r'\(CEST\)\nSubject: Test\nFrom: alice@example.com\nTo: ' + \
            r'alice@example\.com\nDate: Tue, 07 Jan 2020 19:30:03 -0000\n' + \
            r'Message-ID: \n <123456789\.123456\.123456789@example\.com>\n' + \
            r'\n--===============\d+==\nContent-Type: text/rfc822-headers;' + \
            r' protected-headers=\"v1\"\nContent-Disposition: inline\n' + \
            r'(Date: Tue, 07 Jan 2020 19:30:03 -0000\n|Subject: Test\n|' + \
            r'From: alice@example\.com\n|To: alice@example\.com\n|' + \
            r'Message-ID: \n <123456789\.123456\.123456789@example\.com>\n' + \
            r')+\n\n--===============\d+==\nContent-Type: text/plain; ' + \
            r'charset=\"utf-8\"\nContent-Transfer-Encoding: 7bit\n\nThis ' + \
            r'is a test message\.\n--===============\d+==--\n\n' + \
            r'--===============\d+==\nContent-Type: application/pgp-' + \
            r'signature; name=\"signature\.asc\"\nContent-Description: ' + \
            r'OpenPGP digital signature\nContent-Disposition: attachment; ' + \
            r'filename=\"signature\.asc\"\n\n-----BEGIN PGP SIGNATURE-----' + \
            r'\n\n[\w\+/\n=]+-----END PGP SIGNATURE-----\n\n' + \
            r'--===============\d+==--\n'
        self.assertIsNotNone(re.fullmatch(regex, signed))

    def test_sign_encrypt_decrypt(self):
        mail = 'Return-Path: <alice@example.com>\nReceived: from ' + \
            'example.com (example.com [127.0.0.1])\n    by example.com ' + \
            '(Postfix) with ESMTPSA id E8DB612009F\n    for ' + \
            '<alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 ' + \
            '(CEST)\nContent-Type: text/plain; charset="utf-8"\n' + \
            'MIME-Version: 1.0\nContent-Transfer-Encoding: 7bit\n' + \
            'Subject: Test\nFrom: alice@example.com\n' + \
            'To: alice@example.com\nDate: Tue, 07 Jan 2020 19:30:03 ' + \
            '-0000\nMessage-ID:\n ' + \
            '<123456789.123456.123456789@example.com>\n\nThis is a test ' + \
            'message.'
        msg = 'This is a test message.'

        p = Popen(['./gpgmail', '-E', 'alice@example.com', '--gnupghome',
                   self.temp_gpg_homedir.name, '-p', 'test'], stdout=PIPE,
                  stdin=PIPE, stderr=PIPE, encoding='utf8')
        encrypted = p.communicate(input=mail)[0]
        self.assertTrue(msg not in encrypted)

        p = Popen(['./gpgmail', '-p', 'test', '-d', '--gnupghome',
                   self.temp_gpg_homedir.name], stdout=PIPE, stdin=PIPE,
                  stderr=PIPE, encoding='utf8')
        decrypted = p.communicate(input=encrypted)[0]

        self.assertTrue(msg in decrypted)
        regex = r'Content-Type: multipart/mixed; protected-headers="v1";? ' + \
            r'boundary="===============\d+=="\nMIME-Version: 1\.0\n' + \
            r'Return-Path: <alice@example\.com>\nReceived: from ' + \
            r'example\.com \(example.com \[127\.0\.0\.1\]\)\n    by ' + \
            r'example\.com \(Postfix\) with ESMTPSA id E8DB612009F\n    ' + \
            r'for <alice@example\.com>; Tue,  7 Jan 2020 19:30:03 \+0200 ' + \
            r'\(CEST\)\nSubject: Test\nFrom: alice@example\.com\nTo: ' + \
            r'alice@example\.com\nDate: Tue, 07 Jan 2020 19:30:03 -0000\n' + \
            r'Message-ID: \n <123456789\.123456\.123456789@example\.com>\n' + \
            r'\n--===============\d+==\nContent-Type: text/rfc822-headers;' + \
            r' protected-headers="v1"\nContent-Disposition: inline\n(Date:' + \
            r' Tue, 07 Jan 2020 19:30:03 -0000\n|Subject: Test\n|From: ' + \
            r'alice@example\.com\n|To: alice@example\.com\n|Message-ID: \n' + \
            r' <123456789\.123456\.123456789@example\.com>\n)+\n\n' + \
            r'--===============\d+==\nContent-Type: text/plain; ' + \
            r'charset="utf-8"\nContent-Transfer-Encoding: 7bit\n\nThis is ' + \
            r'a test message\.\n--===============\d+==--\n'
        self.assertIsNotNone(re.fullmatch(regex, decrypted))

    def test_encryptheaders(self):
        mail = 'Return-Path: <alice@example.com>\nReceived: from ' + \
            'example.com (example.com [127.0.0.1])\n    by example.com ' + \
            '(Postfix) with ESMTPSA id E8DB612009F\n    for ' + \
            '<alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 ' + \
            '(CEST)\nContent-Type: text/plain; charset="utf-8"\n' + \
            'MIME-Version: 1.0\nContent-Transfer-Encoding: 7bit\n' + \
            'Subject: Test\nFrom: alice@example.com\n' + \
            'To: alice@example.com\nDate: Tue, 07 Jan 2020 19:30:03 ' + \
            '-0000\nMessage-ID:\n ' + \
            '<123456789.123456.123456789@example.com>\n\nThis is a test ' + \
            'message.'
        msg = 'This is a test message.'

        p = Popen(['./gpgmail', '-e', 'alice@example.com', '--gnupghome',
                   self.temp_gpg_homedir.name, '-H'], stdout=PIPE, stdin=PIPE,
                  stderr=PIPE, encoding='utf8')
        encrypted, stderr = p.communicate(input=mail)
        self.assertTrue(msg not in encrypted)
        self.assertIn('Date: ...\n', encrypted)
        self.assertIn('From: ...\n', encrypted)
        self.assertIn('Message-ID: ...\n', encrypted)
        self.assertIn('Subject: ...\n', encrypted)
        self.assertIn('To: ...\n', encrypted)

    def test_encryptfail(self):
        mail = 'Return-Path: <alice@example.com>\nReceived: from ' + \
            'example.com (example.com [127.0.0.1])\n    by example.com ' + \
            '(Postfix) with ESMTPSA id E8DB612009F\n    for ' + \
            '<alice@example.com>; Tue,  7 Jan 2020 19:30:03 +0200 ' + \
            '(CEST)\nContent-Type: text/plain; charset="utf-8"\n' + \
            'MIME-Version: 1.0\nContent-Transfer-Encoding: 7bit\n' + \
            'Subject: Test\nFrom: alice@example.com\n' + \
            'To: alice@example.com\nDate: Tue, 07 Jan 2020 19:30:03 ' + \
            '-0000\nMessage-ID:\n ' + \
            '<123456789.123456.123456789@example.com>\n\nThis is a test ' + \
            'message.'

        p = Popen(['./gpgmail', '-e', 'alice.do@example.com', '--gnupghome',
                   self.temp_gpg_homedir.name, '-H'], stdout=PIPE, stdin=PIPE,
                  stderr=PIPE, encoding='utf8')
        encrypted, stderr = p.communicate(input=mail)
        self.assertEqual(mail, encrypted)


if __name__ == '__main__':
    unittest.main()
