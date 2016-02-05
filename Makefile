SRCDIR=$(shell pwd)/src
INCLUDEDIR=$(shell pwd)/include
PROG=dublin-traceroute
PREFIX=/usr/local

TINS_BASE_DIR=$(shell pwd)/dependencies/libtins
TINS_BUILD_DIR=$(TINS_BASE_DIR)/build
TINS_LIB_DIR=$(TINS_BUILD_DIR)/lib
TINS_AR=$(TINS_LIB_DIR)/libtins.a
TINS_SO=$(TINS_LIB_DIR)/libtins.so
TINS_INCLUDE_DIR=$(TINS_BASE_DIR)/include
#TINS_VERSION=tags/v3.3
TINS_VERSION=master

JSONCPP_BASE_DIR=$(shell pwd)/dependencies/jsoncpp
JSONCPP_BUILD_DIR=$(JSONCPP_BASE_DIR)/dist
JSONCPP_INCLUDE_DIR=$(JSONCPP_BUILD_DIR)

DOCS_DIR=$(shell pwd)/docs

CXXFLAGS=-I. -Iinclude -I$(TINS_INCLUDE_DIR) -I$(JSONCPP_INCLUDE_DIR) -Wall -Werror -pedantic -std=c++11 -ggdb -O0 -Wno-nested-anon-types
LDFLAGS= -lpthread -L$(TINS_LIB_DIR) -ltins
LDFLAGS_STATIC=$(LDFLAGS) -L$(TINS_BUILD_DIR)/lib $(TINS_AR) -static -Wl,-Bdynamic -lc -Wl,-Bstatic -lpcap
LDFLAGS_DYNAMIC=$(LDFLAGS) -ltins -L. -L$(TINS_LIB_DIR) -ldublintraceroute
SOFLAGS=-fPIC
SRCS=$(SRCDIR)/common.cc \
	$(SRCDIR)/dublin_traceroute.cc \
	$(SRCDIR)/traceroute_results.cc \
	$(SRCDIR)/hop.cc \
	$(JSONCPP_BUILD_DIR)/jsoncpp.cpp
TMP=$(SRCS:.cc=.o)
OBJS=$(TMP:.cpp=.o)
HDRS=$(INCLUDEDIR)/dublintraceroute/common.h \
	 $(INCLUDEDIR)/dublintraceroute/exceptions.h \
	 $(INCLUDEDIR)/dublintraceroute/dublin_traceroute.h \
	 $(INCLUDEDIR)/dublintraceroute/traceroute_results.h \
	 $(INCLUDEDIR)/dublintraceroute/icmp_messages.h \
	 $(INCLUDEDIR)/dublintraceroute/hop.h \
	 $(JSONCPP_INCLUDE_DIR)/json/json.h

.PHONY: clean all doc dependencies

all: cli

static: cli_static

libdublintraceroute.so: $(TINS_SO) $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) $(LDFLAGS) -shared

libdublintraceroute.a: $(TINS_AR) $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@.a $(TINS_AR) $(OBJS)

$(JSONCPP_BUILD_DIR)/jsoncpp.o: $(JSONCPP_BUILD_DIR)/jsoncpp.cpp
	$(CXX) -c $(CXXFLAGS) $< -o $@ $(SOFLAGS)

%.o: %.cc
	$(CXX) -c $(CXXFLAGS) $< -o $@ $(SOFLAGS)


%.cc: %.h


cli_static: dependencies $(TINS_AR) $(SRCDIR)/main.o $(OBJS) $(HDRS)
	$(CXX) $(CXXFLAGS) -o $(PROG) $(SRCDIR)/main.o $(OBJS) $(LDFLAGS_STATIC)

cli: dependencies libdublintraceroute.so $(SRCDIR)/main.o $(OBJS) $(HDRS)
	$(CXX) $(CXXFLAGS) -o $(PROG) $(SRCDIR)/main.o $(LDFLAGS_DYNAMIC)

dependencies: submodules $(JSONCPP_BUILD_DIR)

submodules:
	git submodule update --init --recursive

$(TINS_AR): $(TINS_BASE_DIR)
	(	\
		cd $(TINS_BASE_DIR)	&& \
		git checkout $(TINS_VERSION)	&& \
		$(RM) -r $(TINS_BUILD_DIR) 	&& \
		mkdir $(TINS_BUILD_DIR)	&& \
		cd $(TINS_BUILD_DIR)	&& \
		cmake ../ -DLIBTINS_BUILD_SHARED=0 -DLIBTINS_ENABLE_CXX11=1 -DLIBTINS_ENABLE_WPA2=0	&& \
		make	\
	)

$(TINS_SO): $(TINS_BASE_DIR)
	(	\
		cd $(TINS_BASE_DIR)	&& \
		git checkout $(TINS_VERSION)	&& \
		$(RM) -r $(TINS_BUILD_DIR) 	&& \
		mkdir $(TINS_BUILD_DIR)	&& \
		cd $(TINS_BUILD_DIR)	&& \
		cmake ../ -DLIBTINS_BUILD_SHARED=1 -DLIBTINS_ENABLE_CXX11=1 -DLIBTINS_ENABLE_WPA2=0	&& \
		make	\
	)


$(JSONCPP_BUILD_DIR)/jsoncpp.cpp: $(JSONCPP_BUILD_DIR)

$(JSONCPP_BUILD_DIR):
	(	\
		cd $(JSONCPP_BASE_DIR)	&& \
		python amalgamate.py	\
	)

python-extension: all
	(	\
		cd python	&& \
		python setup.py build	\
	)

doc: Doxyfile
	doxygen Doxyfile

install: install-shared-library install-headers install-cli install-python-extension

install-shared-library: libdublintraceroute.so install-libtins
	# install the shared library
	install -d $(DESTDIR)/$(PREFIX)/lib
	install libdublintraceroute.so $(DESTDIR)/$(PREFIX)/lib
	ldconfig

install-libtins: $(TINS_SO)
	(	\
		cd $(TINS_BUILD_DIR)	&& \
		make install	\
	)

install-headers: $(HDRS)
	# install the development headers
	install -d $(DESTDIR)/$(PREFIX)/include/dublintraceroute
	install -t $(DESTDIR)/$(PREFIX)/include/dublintraceroute $(HDRS)

install-cli: cli
	# install the command-line tool
	install -d $(DESTDIR)/$(PREFIX)/bin
	install -t $(DESTDIR)/$(PREFIX)/bin $(PROG)
	# let it use raw socket without root
	if command -v setcap ; \
	then \
		setcap cap_net_raw=ep $(DESTDIR)/$(PREFIX)/bin/$(PROG); \
	else \
		chmod u+s $(DESTDIR)/$(PREFIX)/bin/$(PROG); \
	fi

install-python-extension: python-extension
	# install the python extension
	(	\
		cd python	&& \
		python setup.py install	\
	)

install-all: install install-python-extension

uninstall: uninstall-shared-library uninstall-headers uninstall-cli uninstall-python-extension

uninstall-shared-library:
	$(RM) $(DESTDIR)/$(PREFIX)/lib/libdublintraceroute.so

uninstall-headers:
	$(RM) -r $(DESTDIR)/$(PREFIX)/include/dublintraceroute/

uninstall-cli:
	$(RM) $(DESTDIR)/$(PREFIX)/bin/$(PROG)

uninstall-python-extension:
	# TODO uninstall the Pyton extension

clean:
	$(RM) -r $(OBJS) $(PROG) $(DOCS_DIR) $(JSONCPP_BUILD_DIR) libdublintraceroute.so libdublintraceroute.a

distclean: clean
	$(RM) -r $(TINS_BUILD_DIR)

