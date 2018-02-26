package dublintraceroute

import (
	"encoding/json"
	"net"
)

type Probe struct {
	From    net.IP `json:"from"`
	SrcPort uint16 `json:"srcport"`
	DstPort uint16 `json:"dstport"`
	TTL     uint8  `json:"ttl"`
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
