#!/bin/bash
set -exu

if [ $UID -ne 0 ]
then
    sudo $0 $@
    exit $?
fi

if [ ! -d output ]
then
    mkdir output
fi
docker run -v "${PWD}/output:/output" -it insomniacslk/dublin-traceroute $@
