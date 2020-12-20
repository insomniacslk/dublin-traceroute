#!/bin/bash
set -exu

if [ $UID -ne 0 ]
then
    sudo $0 $@
    exit $?
fi

docker build -t insomniacslk/dublin-traceroute -f Dockerfile . $@

