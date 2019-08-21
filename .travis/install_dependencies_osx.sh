#!/bin/sh

# dependencies are now installed in .travis.yml . Just show the package content
# here. `brew update` is done in .travis.yml with the brew addon.
brew install --build-from-source libtins
brew uninstall json-c
brew install --build-from-source jsoncpp
