package dublintraceroute

import (
	"encoding/json"
	"net"
)

type Probe struct {
	SrcAddr net.IP `json:"srcaddr"`
	DstAddr net.IP `json:"dstaddr"`
	SrcPort uint16 `json:"srcport"`
	DstPort uint16 `json:"dstport"`
	NAT     bool   `json:"nat"`
}

type Results struct {
	Flows map[uint16][]Probe `json:"flows"`
}

func (r *Results) ToJson() string {
	b, err := json.Marshal(r)
	if err != nil {
		return ""
	}
	return string(b)
}
