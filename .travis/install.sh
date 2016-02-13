#!/bin/bash

if [[ $TRAVIS_OS_NAME == 'linux' ]]
then
    if [ "$CXX" = "g++" ]
    then
        sudo apt-get install -qq g++-4.8
    elif [ "$CXX" = "clang" ]
    then
        sudo apt-get install --allow-unauthenticated -qq clang-3.4
    fi
fi

if [ "$CXX" = "g++" ]
then
    export CXX="g++-4.8"
elif [ "$CXX" = "clang" ]
then
    export CXX="clang++-3.4"
fi
