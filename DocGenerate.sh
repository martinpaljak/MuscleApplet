#!/bin/sh

rm -rf doc
mkdir doc
cd doc

SRCDIR=../src/com/musclecard/CardEdge
SOURCES=$(echo $SRCDIR/{ObjectManager,MemoryManager,CardEdge}.java)

source ../Java.conf

ARGS="-private -sourcepath $APIDIR -version -author -nodeprecated"

# print executed commands
set -x

$JAVADOC $ARGS $SOURCES

