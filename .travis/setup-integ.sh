#!/bin/bash
set -exu

if [ $UID -ne 0 ]
then
    sudo "$0" "$@"
    exit $?
fi
action=${1:-}

ifname=dubtr
netns=dubtr
ula_prefix=${ULA_PREFIX:-fd4f:6b37:542c:b643}

ip netns delete "${netns}" || true
killall -9 routest || true # this may be a bit too brutal...
[[ "${action}" == "teardown" ]] && exit 0

ip netns add "${netns}"
ip -n "${netns}" link add "${ifname}" type veth peer name upstream
ip -n "${netns}" addr add "${ula_prefix}:a::1/64" dev "${ifname}"
ip -n "${netns}" addr add "10.0.2.1/24" dev "${ifname}"
ip -n "${netns}" link set "${ifname}" up
ip -n "${netns}" link set upstream up
ip -n "${netns}" link set lo up
ip -n "${netns}" route add "10.0.0.0/8" dev "${ifname}"
ip -n "${netns}" route add default dev "${ifname}"

ip netns exec "${netns}"\
    iptables -A OUTPUT \
        -p udp --dport 33434:33634 \
        -d 8.8.8.8 \
        -j NFQUEUE --queue-num 101


# set up ARP entries for test hops and target
setup_arp() {
    addr=${1}
    ip netns exec "${netns}" arp -d "${addr}" || true
    ip netns exec "${netns}" arp -i "${ifname}" -Ds "${addr}" "${ifname}"
}

# this assumes we are running from the .travis directory, and looks for test
# data in ../integ/test_data .
addrs=$(for file in ../integ/test_data/config_*.json; do
    jq '.[].reply.src' < "${file}"
done | sort -u | tr -d '"')

for addr in ${addrs}
do
    setup_arp "${addr}"
done

ip netns exec "${netns}" arp -na
