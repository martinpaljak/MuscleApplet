#!/bin/sh

#    Verify.sh, script to verify a .jar (JavaCard) file
#    Copyright (C) 2002  Ludovic Rousseau <ludovic.rousseau@free.fr>
#
#    This program is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program; if not, write to the Free Software
#    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

# Applet dependent data
APPLET=com.musclecard.CardEdge

OUTPUT_DIR=./out


source Java.conf

# applet name with '.' converted in '/'
# com.sun.javacard.samples.CardEdge -> com/sun/javacard/samples/CardEdge
APPLET_SLASH=$(ConvertDotInSlash $APPLET)

# last element of applet name
# com.sun.javacard.samples.CardEdge -> CardEdge
APPLET_NAME=$(basename $APPLET_SLASH)

# print executed commands
set -x

$VERIFYCAP -verbose $APIDIR/java/lang/javacard/lang.exp \
  $APIDIR/javacard/framework/javacard/framework.exp \
  $APIDIR/javacardx/crypto/javacard/crypto.exp \
  $APIDIR/javacard/security/javacard/security.exp \
  \
  $OUTPUT_DIR/$APPLET_SLASH/javacard/$APPLET_NAME.exp \
  $OUTPUT_DIR/$APPLET_SLASH/javacard/$APPLET_NAME.jar

