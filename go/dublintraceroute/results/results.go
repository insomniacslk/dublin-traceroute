package results

import (
	"encoding/json"
	"net"
	"time"
)

// TODO refactor this into a `results` subpackage

type IP struct {
	SrcIP net.IP `json:"src"`
	DstIP net.IP `json:"dst"`
	ID    uint16 `json:"id"`
	TTL   uint8  `json:"ttl"`
}

type UDP struct {
	SrcPort uint16 `json:"sport"`
	DstPort uint16 `json:"dport"`
}

type ICMP struct {
	Code        uint8           `json:"code"`
	Type        uint8           `json:"type"`
	Description string          `json:"description"`
	Extensions  []ICMPExtension `json:"extensions"`
	MPLSLabels  []MPLSLabel     `json:"mpls_labels"`
}

type ICMPExtension struct {
	Class   uint8  `json:"class"`
	Type    uint8  `json:"type"`
	Payload []byte `json:"payload"`
	Size    uint8  `json:"size"`
}

type MPLSLabel struct {
	BottomOfStack uint8  `json:"bottom_of_stack"`
	Experimental  uint8  `json:"experimental"`
	Label         uint32 `json:"label"`
	TTL           uint8  `json:"ttl"`
}

type Packet struct {
	Timestamp time.Time `json:"timestamp"`
	IP        IP        `json:"ip"`
	UDP       UDP       `json:"udp,omitempty"`
	ICMP      ICMP      `json:"icmp,omitempty"`
	// TODO add TCP, HTTP, DNS
}

type Probe struct {
	Flowhash             uint16  `json:"flowhash"`
	IsLast               bool    `json:"is_last"`
	Name                 string  `json:"name"`
	NATID                uint16  `json:"nat_id"`
	RttUsec              uint64  `json:"rtt_usec"`
	Sent                 Packet  `json:"sent"`
	Received             *Packet `json:"received"`
	ZeroTTLForwardingBug bool    `json:"zerottl_forwarding_bug"`
}

type Results struct {
	Flows      map[uint16][]Probe `json:"flows"`
	compressed bool
}

func (r *Results) compress() {
	for k, v := range r.Flows {
		for idx, e := range v {
			if e.IsLast {
				v = v[:idx]
				r.Flows[k] = v
			}
		}
	}
	r.compressed = true
}

func (r *Results) ToJson(compress bool, indent string) string {
	if compress {
		if !r.compressed {
			r.compress()
		}
	}
	b, err := json.MarshalIndent(r, "", indent)
	if err != nil {
		return ""
	}
	return string(b)
}
