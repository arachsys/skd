VERSION = 1.2

CC = gcc
CFLAGS = -g -Os -Wall -DVERSION=\"${VERSION}\"
LDFLAGS =

PREFIX =
BINDIR = /bin
DESTDIR =

skd: skd.c

install: skd
	mkdir -p ${DESTDIR}${BINDIR}
	install -m 755 -s skd ${DESTDIR}${BINDIR}

clean:
	rm -f skd

.PHONY: install clean
