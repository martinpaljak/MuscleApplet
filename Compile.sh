#!/bin/sh

#    Compile.sh, script to compile a javacard applet
#    Copyright (C) 2002-2003  Ludovic Rousseau <ludovic.rousseau@free.fr>
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

APPLET_SRC=$(pwd)/src/com/musclecard/CardEdge/*.java
OUTPUT_DIR=./out

source Java.conf

# exit if error
set -e

if [ ! -d "$OUTPUT_DIR" ]
then
	mkdir "$OUTPUT_DIR"
fi

# print executed commands
set -x

$JAVAC -verbose -classpath $CLASSPATH:$JC21/lib/api21.jar -g -d "$OUTPUT_DIR" $APPLET_SRC

