# =======================> Customize here, please

APPLET_VERSION_MAJOR=0
APPLET_VERSION_MINOR=5
PROTO_VERSION_MAJOR=0
PROTO_VERSION_MINOR=1

# Total Object Memory Size
OBJECT_MEMORY_SIZE=4096

# Final name of .tar.gz archive
PACKAGE=CardEdgeApplet

# Name of Java Card Applet
JAVA_APPLET=CardEdge
# Package into which Applet resides
JAVA_PACKAGE=com.sun.javacard.samples.$(JAVA_APPLET)

#   Selectively enable algorithms (what is disabled returns SW_UNSUPPORTED_FEATURE)
# CPPFLAGS += -DWITH_DSA -DWITH_RSA -DWITH_DES -DWITH_3DES -DWITH_3DES3
CPPFLAGS += -DWITH_RSA -DWITH_DES -DWITH_3DES

#   Selectively enable directions (what is disabled returns SW_UNSUPPORTED_FEATURE)
# CPPFLAGS += -DWITH_ENCRYPT -DWITH_DECRYPT -DWITH_SIGN
CPPFLAGS += -DWITH_ENCRYPT -DWITH_DECRYPT -DWITH_SIGN

#   Disable ExtAuthenticate command, if unused and more space is required on board
#CPPFLAGS += -DWITH_EXT_AUTH

#   Disable PIN Policy enforcement, if unneeded and more space is required on board
CPPFLAGS += -UWITH_PIN_POLICY

# =======================> End of customizations

JAVA_DIR=`echo $(JAVA_PACKAGE) | sed -e 's/\./\//g'`

DIST_ARCHIVE=$(PACKAGE)-$(APPLET_VERSION_MAJOR).$(APPLET_VERSION_MINOR)-bin
SRCDIST_ARCHIVE=$(PACKAGE)-$(APPLET_VERSION_MAJOR).$(APPLET_VERSION_MINOR)
DIST_BIN_FILES=$(wildcard *.class)
DIST_DOC_FILES=README LICENSE AUTHORS

JAVADOC_OUTPUT_DIR=doc

# Don't generate #line directives
CPPFLAGS += -P
# Enable redundant debug checks (increases Applet size, decreases performance)
# When such a check fails, we get a SW_INTERNAL_ERROR
#CPPFLAGS += -DAPPLET_DEBUG=1

# Set version information for GetStatus
CPPFLAGS += -DAPPLET_VERSION_MAJOR=$(APPLET_VERSION_MAJOR)
CPPFLAGS += -DAPPLET_VERSION_MINOR=$(APPLET_VERSION_MINOR)
CPPFLAGS += -DPROTO_VERSION_MAJOR=$(PROTO_VERSION_MAJOR)
CPPFLAGS += -DPROTO_VERSION_MINOR=$(PROTO_VERSION_MINOR)

# Set total object memory size
CPPFLAGS += -DOBJECT_MEMORY_SIZE=$(OBJECT_MEMORY_SIZE)

# Set Java Package and Applet name information
CPPFLAGS += -DJAVA_PACKAGE=$(JAVA_PACKAGE)
CPPFLAGS += -DJAVA_APPLET=$(JAVA_APPLET)

JCFLAGS=-g
JCCLASSPATH=-classpath /home/ehersked/jc211/bin/jc_api_21.jar:$(shell pwd)

all: CardEdge.java MemoryManager.java ObjectManager.java

test: $(patsubst %.java, %.class, $(wildcard test*.java))

%.class: %.java
	javac $(JCFLAGS) $(JCCLASSPATH) $<

%.java : %.src Makefile
	cpp $(CPPFLAGS) -o $@ $<
#	sed -e 's/#.*//g' < /tmp/file.tmp > $@

testMemoryManager.class: MemoryManager.class

dist-bin:
	rm -rf /tmp/$(DIST_ARCHIVE) /tmp/$(DIST_ARCHIVE).tgz
	mkdir -p /tmp/$(DIST_ARCHIVE)/$(JAVA_DIR)
	cp -a $(DIST_BIN_FILES) /tmp/$(DIST_ARCHIVE)/$(JAVA_DIR)
	cp -a $(DIST_DOC_FILES) /tmp/$(DIST_ARCHIVE)/$(JAVA_DIR)
	cp -a $(DIST_DOC_FILES) /tmp/$(DIST_ARCHIVE)
	cd /tmp && tar -czf $(DIST_ARCHIVE).tgz $(DIST_ARCHIVE)
	rm -rf /tmp/$(DIST_ARCHIVE)
	echo ""
	echo "Built binary distribution package: /tmp/$(DIST_ARCHIVE).tgz"
	echo ""

dist-src:
	rm -rf /tmp/$(SRCDIST_ARCHIVE) /tmp/$(SRCDIST_ARCHIVE).tgz
	mkdir -p /tmp/$(SRCDIST_ARCHIVE)/$(JAVA_DIR)
	cp -a * /tmp/$(SRCDIST_ARCHIVE)/$(JAVA_DIR)
	cd /tmp/$(SRCDIST_ARCHIVE)/$(JAVA_DIR) && make clean
	cd /tmp && tar -czf $(SRCDIST_ARCHIVE).tgz $(SRCDIST_ARCHIVE)
	rm -rf /tmp/$(SRCDIST_ARCHIVE)
	echo ""
	echo "Built souce package: /tmp/$(SRCDIST_ARCHIVE).tgz"
	echo ""

dist:
	echo "Type one of 'make dist-src' or 'make dist-bin'"

clean:
	rm -f *~ *.class *.nodef

%.nodef : %.src Makefile
	sed -e 's/^\#.*$\//g' -e s/JAVA_APPLET/$(JAVA_APPLET)/g < $< > $@

jdoc: $(patsubst %.src, %.nodef, $(wildcard *.src))
	javadoc -private -d $(JAVADOC_OUTPUT_DIR) $^
