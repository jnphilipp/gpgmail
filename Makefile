BINDIR?=/usr/bin
DOCDIR?=/usr/share/doc
MANDIR?=/usr/share/man


clean:
	@rm -rf ./build


deb: build/package/DEBIAN/control
	fakeroot dpkg-deb -b build/package build/gpgmail.deb
	lintian -Ivi --suppress-tags debian-changelog-file-missing-or-wrong-name build/gpgmail.deb


install: build/copyright build/changelog build/gpgmail.1.gz
	@apt install python3-gnupg

	@install -m 0755 gpgmail ${BINDIR}/gpgmail
	@install -m 0755 gpgmail-postfix ${BINDIR}/gpgmail-postfix
	@install -Dm 0644 build/changelog.gz "${DOCDIR}"/gpgmail/changelog.gz
	@install -Dm 0644 build/copyright "${DOCDIR}"/gpgmail/copyright
	@install -Dm 0644 build/gpgmail.1.gz "${MANDIR}"/man1/gpgmail.1.gz

	@echo "gpgmail install completed."


uninstall:
	@apt remove python3-gnupg
	@rm -r "${DOCDIR}"/gpgmail
	@rm "${BINDIR}"/gpgmail
	@rm "${BINDIR}"/gpgmail-postfix
	@rm "${MANDIR}"/man1/gpgmail.1.gz

	@echo "gpgmail uninstall completed."


build:
	@mkdir build


build/changelog: build
	@git log --oneline --no-merges --format="%h %d %ai%n    %an <%ae>%n    %s" > build/changelog
	@cat build/changelog | gzip -n9 > build/changelog.gz


build/copyright: build
	@echo "Upstream-Name: gpgmail\nSource: https://github.com/jnphilipp/gpgmail\n\nFiles: *\nCopyright: 2019 Nathanael Philipp (jnphilipp) <nathanael@philipp.land>\nLicense: GPL-3+\n This program is free software: you can redistribute it and/or modify\n it under the terms of the GNU General Public License as published by\n the Free Software Foundation, either version 3 of the License, or\n any later version.\n\n This program is distributed in the hope that it will be useful,\n but WITHOUT ANY WARRANTY; without even the implied warranty of\n MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the\n GNU General Public License for more details.\n\n You should have received a copy of the GNU General Public License\n along with this program. If not, see <http://www.gnu.org/licenses/>.\n On Debian systems, the full text of the GNU General Public\n License version 3 can be found in the file\n '/usr/share/common-licenses/GPL-3'." > build/copyright
	@echo "[COPYRIGHT]\nThis program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.\n\nThis program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.\n\nYou should have received a copy of the GNU General Public License along with this program. If not, see http://www.gnu.org/licenses/." > build/copyright.h2m

build/gpgmail.1.gz: build build/copyright
	help2man ./gpgmail -i build/copyright.h2m -n "Encrypt/Decrypt GPG/MIME emails." | gzip -n9 > build/gpgmail.1.gz


build/package/DEBIAN: build
	@mkdir -p build/package/DEBIAN


build/package/DEBIAN/control: build/package/DEBIAN/md5sums
	@echo "Package: gpgmail" > build/package/DEBIAN/control
	@echo "Version: `git describe --tags | awk '{print substr($$0,2)}'`" >> build/package/DEBIAN/control
	@echo "Section: mail" >> build/package/DEBIAN/control
	@echo "Priority: optional" >> build/package/DEBIAN/control
	@echo "Architecture: all" >> build/package/DEBIAN/control
	@echo "Depends: python3 (>= 3), python3-gnupg" >> build/package/DEBIAN/control
	@echo "Installed-Size: `du -csk build/package/usr | grep -oE "[0-9]+\stotal" | cut -f 1`" >> build/package/DEBIAN/control
	@echo "Maintainer: Nathanael Philipp <nathanael@philipp.land>" >> build/package/DEBIAN/control
	@echo "Homepage: https://github.com/jnphilipp/gpgmail" >> build/package/DEBIAN/control
	@echo "Description: Encrypting and Decrypting emails using PGP/MIME" >> build/package/DEBIAN/control
	@echo " This tool can encrypt and decrypt emails using PGP/MIME. Emails inputed from\n stdin and outputed to stdout. When encrypting, the tool preserves all headers\n in the original email in the encrypted part, and copies relevant headers to\n the output. When decrypting, any headers are ignored, and only the encrypted\n headers are restored.\n Encrypted email are not reencrypted. This is check based on the content type." >> build/package/DEBIAN/control


build/package/DEBIAN/md5sums: gpgmail build/copyright build/changelog build/gpgmail.1.gz build/package/DEBIAN
	@install -Dm 0755 gpgmail build/package"${BINDIR}"/gpgmail
	@install -Dm 0755 gpgmail-postfix build/package"${BINDIR}"/gpgmail-postfix
	@install -Dm 0644 build/changelog.gz build/package"${DOCDIR}"/gpgmail/changelog.gz
	@install -Dm 0644 build/copyright build/package"${DOCDIR}"/gpgmail/copyright
	@install -Dm 0644 build/gpgmail.1.gz build/package"${MANDIR}"/man1/gpgmail.1.gz

	@mkdir -p build/package/DEBIAN
	@md5sum `find build/package -type f -not -path "*DEBIAN*"` > build/md5sums
	@sed -e "s/build\/package\///" build/md5sums > build/package/DEBIAN/md5sums
	@chmod 644 build/package/DEBIAN/md5sums
