#!/bin/bash
set -exu

# the Linux dependencies are now installed in .travis.yml
# so here we only set up GOPATH for the integration tests

mkdir -p "${GOPATH}/src/github.com/insomniacslk"
cd "${GOPATH}/src/github.com/insomniacslk"
ln -s "${TRAVIS_BUILD_DIR}" dublin-traceroute
cd dublin-traceroute/go/dublintraceroute/cmd/routest
go get -v ./...
