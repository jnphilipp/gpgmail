SHELL:=/bin/bash

BASH_COMPLETION_DIR?=/usr/share/bash-completion.d
BIN_DIR?=/usr/bin
DOC_DIR?=/usr/share/doc
MAN_DIR?=/usr/share/man
SHARE_DIR?=/usr/share
DEST_DIR?=


ifdef VERBOSE
  Q :=
else
  Q := @
endif


clean:
	$(Q)rm -rf ./build
	$(Q)find . -name __pycache__ -exec rm -rf {} \;


test:
	python3 -m unittest


deb: test build/package/DEBIAN/control
	$(Q)fakeroot dpkg-deb -b build/package build/gpgmail.deb
	$(Q)lintian -Ivi build/gpgmail.deb
	$(Q)dpkg-sig -s builder build/gpgmail.deb
	@echo "gpgmail.deb completed."


install: build/copyright build/changelog.gz build/gpgmail.1.gz build/gpgmail-postfix.1.gz
	$(Q)install -Dm 0755 gpgmail ${DEST_DIR}${BIN_DIR}/gpgmail
	$(Q)install -Dm 0755 gpgmail-postfix ${DEST_DIR}${BIN_DIR}/gpgmail-postfix

	$(Q)install -Dm 0644 build/changelog.gz ${DEST_DIR}${DOC_DIR}/gpgmail/changelog.gz
	$(Q)install -Dm 0644 build/copyright ${DEST_DIR}${DOC_DIR}/gpgmail/copyright

	$(Q)install -Dm 0644 build/gpgmail.1.gz ${DEST_DIR}${MAN_DIR}/man1/gpgmail.1.gz
	$(Q)install -Dm 0644 build/gpgmail-postfix.1.gz ${DEST_DIR}${MAN_DIR}/man1/gpgmail-postfix.1.gz

	@echo "gpgmail install completed."


uninstall:
	$(Q)rm -r ${DEST_DIR}${DOC_DIR}/gpgmail
	$(Q)rm ${DEST_DIR}${BIN_DIR}/gpgmail
	$(Q)rm ${DEST_DIR}${BIN_DIR}/gpgmail-postfix
	$(Q)rm ${DEST_DIR}${MAN_DIR}/man1/gpgmail.1.gz

	@echo "gpgmail uninstall completed."


build:
	$(Q)mkdir build


build/copyright: build
	$(Q)echo "Upstream-Name: gpgmail" > build/copyright
	$(Q)echo "Source: https://github.com/jnphilipp/gpgmail" >> build/copyright
	$(Q)echo "Files: *" >> build/copyright
	$(Q)echo "Copyright: 2019-2022 J. Nathanael Philipp (jnphilipp) <nathanael@philipp.land>" >> build/copyright
	$(Q)echo "License: GPL-3+" >> build/copyright
	$(Q)echo " This program is free software: you can redistribute it and/or modify" >> build/copyright
	$(Q)echo " it under the terms of the GNU General Public License as published by" >> build/copyright
	$(Q)echo " the Free Software Foundation, either version 3 of the License, or" >> build/copyright
	$(Q)echo " any later version." >> build/copyright
	$(Q)echo "" >> build/copyright
	$(Q)echo " This program is distributed in the hope that it will be useful," >> build/copyright
	$(Q)echo " but WITHOUT ANY WARRANTY; without even the implied warranty of" >> build/copyright
	$(Q)echo " MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the" >> build/copyright
	$(Q)echo " GNU General Public License for more details." >> build/copyright
	$(Q)echo "" >> build/copyright
	$(Q)echo " You should have received a copy of the GNU General Public License" >> build/copyright
	$(Q)echo " along with this program. If not, see <http://www.gnu.org/licenses/>." >> build/copyright
	$(Q)echo " On Debian systems, the full text of the GNU General Public" >> build/copyright
	$(Q)echo " License version 3 can be found in the file" >> build/copyright
	$(Q)echo " '/usr/share/common-licenses/GPL-3'." >> build/copyright


build/copyright.h2m: build
	$(Q)echo "[COPYRIGHT]" > build/copyright.h2m
	$(Q)echo "This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version." >> build/copyright.h2m
	$(Q)echo "" >> build/copyright.h2m
	$(Q)echo "This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details." >> build/copyright.h2m
	$(Q)echo "" >> build/copyright.h2m
	$(Q)echo "You should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/." >> build/copyright.h2m

build/changelog.Debian.gz: build
	$(Q)declare TAGS=(`git tag`); for ((i=$${#TAGS[@]};i>=0;i--)); do if [ $$i -eq 0 ]; then git log $${TAGS[$$i]} --no-merges --format="gpgmail ($${TAGS[$$i]}-%h) unstable; urgency=medium%n%n  * %s%n    %b%n -- %an <%ae>  %aD%n" | sed "/^\s*$$/d" >> build/changelog; elif [ $$i -eq $${#TAGS[@]} ]; then git log $${TAGS[$$i-1]}..HEAD --no-merges --format="gpgmail ($${TAGS[$$i-1]}-%h) unstable; urgency=medium%n%n  * %s%n    %b%n -- %an <%ae>  %aD%n" | sed "/^\s*$$/d" >> build/changelog; else git log $${TAGS[$$i-1]}..$${TAGS[$$i]} --no-merges --format="gpgmail ($${TAGS[$$i]}-%h) unstable; urgency=medium%n%n  * %s%n    %b%n -- %an <%ae>  %aD%n" | sed "/^\s*$$/d" >> build/changelog; fi; done
	$(Q)cat build/changelog | gzip -n9 > build/changelog.Debian.gz


build/gpgmail.1.gz: build build/copyright.h2m
	$(Q)help2man ./gpgmail -i build/copyright.h2m -n "Encrypt/Decrypt GPG/MIME emails." | gzip -n9 > build/gpgmail.1.gz


build/gpgmail-postfix.1.gz: build build/copyright.h2m
	$(Q)help2man ./gpgmail-postfix -i build/copyright.h2m -n "Postfix filter script for gpgmail." | gzip -n9 > build/gpgmail-postfix.1.gz


build/package/DEBIAN: build
	$(Q)mkdir -p build/package/DEBIAN


build/package/DEBIAN/md5sums: gpgmail gpgmail-postfix build/copyright build/changelog.Debian.gz build/gpgmail.1.gz build/gpgmail-postfix.1.gz build/package/DEBIAN
	$(Q)make install DEST_DIR=build/package

	$(Q)mkdir -p build/package/DEBIAN
	$(Q)md5sum `find build/package -type f -not -path "*DEBIAN*"` > build/md5sums
	$(Q)sed -e "s/build\/package\///" build/md5sums > build/package/DEBIAN/md5sums
	$(Q)chmod 644 build/package/DEBIAN/md5sums

build/package/DEBIAN/control: build/package/DEBIAN/md5sums
	$(Q)echo "Package: gpgmail" > build/package/DEBIAN/control
	$(Q)echo "Version: `git describe --tags`-`git log --format=%h -1`" >> build/package/DEBIAN/control
	$(Q)echo "Section: mail" >> build/package/DEBIAN/control
	$(Q)echo "Priority: optional" >> build/package/DEBIAN/control
	$(Q)echo "Architecture: all" >> build/package/DEBIAN/control
	$(Q)echo "Depends: python3 (<< 3.11) (>= 3.7), python3-gnupg, gnupg" >> build/package/DEBIAN/control
	$(Q)echo "Installed-Size: `du -sk build/package/usr | grep -oE "[0-9]+"`" >> build/package/DEBIAN/control
	$(Q)echo "Maintainer: J. Nathanael Philipp (jnphilipp) <nathanael@philipp.land>" >> build/package/DEBIAN/control
	$(Q)echo "Homepage: https://github.com/jnphilipp/gpgmail" >> build/package/DEBIAN/control
	$(Q)echo "Description: Encrypting and Decrypting emails using PGP/MIME" >> build/package/DEBIAN/control
	$(Q)echo " This tool can encrypt and decrypt emails using PGP/MIME. Emails input from" >> build/package/DEBIAN/control
	$(Q)echo " stdin and output to stdout. When encrypting, the tool preserves all headers" >> build/package/DEBIAN/control
	$(Q)echo " in the original email in the encrypted part, and copies relevant headers to" >> build/package/DEBIAN/control
	$(Q)echo " the output. When decrypting, any headers are ignored, and only the encrypted" >> build/package/DEBIAN/control
	$(Q)echo " headers are restored." >> build/package/DEBIAN/control
	$(Q)echo " Encrypted email are not re-encrypted. This is check based on the content type." >> build/package/DEBIAN/control
