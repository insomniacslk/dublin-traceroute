#!/bin/bash

if [[ $TRAVIS_OS_NAME == 'linux' ]]
then
    if [ "$CXX" == "g++" ]
    then
        sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
    elif [ "$CXX" == "clang++" ]
    then
        sudo add-apt-repository -y ppa:h-rayflood/llvm
    fi
    sudo apt-get update -qq
fi
