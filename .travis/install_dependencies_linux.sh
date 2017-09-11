#!/bin/bash

# install libtins
git clone https://github.com/mfontanini/libtins.git
cd libtins
git checkout tags/v3.4
mkdir build
cd build
cmake ..
make
sudo make install

# install jsoncpp
git clone https://github.com/open-source-parsers/jsoncpp.git
cd jsoncpp
mkdir build
cd build
cmake .. -DBUILD_SHARED_LIBS=on
make
sudo make install
