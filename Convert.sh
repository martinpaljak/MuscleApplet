#!/bin/sh

#    Convert.sh, script to convert a .class (Java) into .cap (JavaCard)
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
PACKAGE_AID="0xA0:00:00:00:01"
APPLET_AID=$PACKAGE_AID:01
VERSION=1.0
APPLET=com.musclecard.CardEdge

OUTPUT_DIR=./out

source Java.conf

# applet name with '.' converted in '/'
# com.musclecard.CardEdge -> com/musclecard/CardEdge
APPLET_SLASH=$(ConvertDotInSlash $APPLET)

# last element of applet name
# com.musclecard.CardEdge -> CardEdge
APPLET_NAME=$(basename $APPLET_SLASH)

# exit on the first error
set -e

# print executed commands
set -x

$CONVERTER -verbose -classdir out -exportpath $APIDIR \
  -applet $APPLET_AID $APPLET_NAME -out CAP EXP JCA \
  $APPLET $PACKAGE_AID $VERSION

$CAPGEN \
  -o $OUTPUT_DIR/$APPLET_SLASH/javacard/$APPLET_NAME.jar \
  $OUTPUT_DIR/$APPLET_SLASH/javacard/$APPLET_NAME.jca

