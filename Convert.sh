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

# $Id$

# Applet dependent data
PACKAGE_AID="0xA0:00:00:00:01"
APPLET_AID=$PACKAGE_AID:01
VERSION=1.0
APPLET=com.musclecard.CardEdge

OUTPUT_DIR=./out


# System dependent data
JAVA_HOME=${JAVA_HOME:-/usr/local/tools/jdk/j2sdk1.3.1}
export JAVA_HOME

JC21=${JC21:-/usr/local/tools/JavaCard/java_card_kit-2_1_2}
JC21BIN=$JC21/bin

CONVERTER=$JC21BIN/converter
CAPGEN=$JC21BIN/capgen

# applet name with '.' converted in '/'
# com.sun.javacard.samples.CardEdge -> com/sun/javacard/samples/CardEdge
APPLET_SLASH=$(echo $APPLET | sed -e 's/\./\//g' )

# last element of applet name
# com.sun.javacard.samples.CardEdge -> CardEdge
APPLET_NAME=$(basename $APPLET_SLASH)

# exit on the first error
set -e

# print executed commands
set -x

$CONVERTER -verbose -classdir out -exportpath $JC21/api21_export_files \
  -applet $APPLET_AID $APPLET_NAME -out CAP EXP JCA \
  $APPLET $PACKAGE_AID $VERSION

$CAPGEN \
  -o $OUTPUT_DIR/$APPLET_SLASH/javacard/$APPLET_NAME.jar \
  $OUTPUT_DIR/$APPLET_SLASH/javacard/$APPLET_NAME.jca

