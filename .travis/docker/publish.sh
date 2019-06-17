#!/bin/bash
set -exu

if [ $UID -ne 0 ]
then
    sudo $0 $@
    exit $?
fi

VERSION=latest
docker tag insomniacslk/dublin-traceroute \
    insomniacslk/dublin-traceroute:"${VERSION}"
docker push \
    insomniacslk/dublin-traceroute:"${VERSION}"
