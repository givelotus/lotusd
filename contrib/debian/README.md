
Debian
====================
This directory contains files used to package lotusd/lotus-qt
for Debian-based Linux systems. If you compile lotusd/lotus-qt yourself, there are some useful files here.

## bitcoincash: URI support ##


lotus-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install lotus-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your lotus-qt binary to `/usr/bin`
and the `../../share/pixmaps/lotus128.png` to `/usr/share/pixmaps`

lotus-qt.protocol (KDE)

