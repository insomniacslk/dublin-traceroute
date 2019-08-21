#!/bin/bash
set -exu

cmd="${1:-}"

./setup-integ.sh
[[ "${cmd}" == "interactive" ]] && read -r -p "Netns setup completed. Press enter to proceed with the tests"
(
    cd ../integ
    sudo -E ip netns exec dubtr "$(which go)" test -args -gocmd "$(which go)"
)
./setup-integ.sh teardown
