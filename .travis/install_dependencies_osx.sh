#!/bin/sh

brew update
brew install --HEAD libtins
brew uninstall json-c
brew install jsoncpp
