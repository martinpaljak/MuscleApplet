#!/bin/sh

# Use this script to recompile the applet
# You will need to have a Gemplus RAD III installed

# $Id$

OUT=$(pwd)/out
SRC=$(pwd)/src/*.java

. ~/.gxp_rad_profile

LP=""
export LP
. $RAD_HOME/bin/GxpRADInit.sh
unset LP

echo '-======================================-'
echo '        Compiling Java files'
echo '-======================================-'
$JAVA_BIN/javac -classpath $RAD_HOME/lib/gse/gse_gxp211_pk.jar -g -d $OUT $SRC

