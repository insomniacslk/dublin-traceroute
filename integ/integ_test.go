package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/results"
	"github.com/stretchr/testify/require"
)

// WARNING: this test is meant to run on CI, don't run it on your production
// machines or it will mess up your iptables rules.

const NfQueueNum int64 = 101

var (
	one = 1
)

var (
	// TODO detect this at start-up
	needSudo = false

	defaultDubTrTimeout     = 10 * time.Second
	goDublinTraceroutePath  = "../go/dublintraceroute/cmd/dublin-traceroute/dublin-traceroute"
	cppDublinTraceroutePath = "../build/dublin-traceroute"
)

func setup() {
	cl := []string{"iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "33434:33634", "-d", "8.8.8.8", "-j", "NFQUEUE", "--queue-num", strconv.FormatInt(NfQueueNum, 10)}
	if needSudo {
		cl = append([]string{"sudo"}, cl...)
	}
	log.Printf("Running %v", cl)
	if err := exec.Command(cl[0], cl[1:]...).Run(); err != nil {
		log.Panicf("Failed to run iptables: %v", err)
	}
}

func shutdown() {
	// nothing to do here
}

func TestMain(m *testing.M) {
	setup()
	code := m.Run()
	shutdown()
	os.Exit(code)
}

type testConfig struct {
	// timeout for dublin-traceroute
	timeout time.Duration
	// arguments to routest
	configFile string
	// arguments to dublin-traceroute
	paths   *int
	minTTL  *int
	maxTTL  *int
	srcPort *int
	dstPort *int
	delay   *int
	target  string
}

func runWithConfig(useGoImplementation bool, cfg testConfig) ([]byte, []byte, error) {
	// validate to config
	if cfg.timeout <= 0 {
		cfg.timeout = defaultDubTrTimeout
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// run routest
	cl := []string{"routest", "-i", "lo", "-c", cfg.configFile, "-q", strconv.FormatInt(NfQueueNum, 10)}
	if needSudo {
		cl = append([]string{"sudo"}, cl...)
	}
	log.Printf("Running routest with args %v", cl[1:])
	rCmd := exec.CommandContext(ctx, cl[0], cl[1:]...)
	rCmd.Stdout, rCmd.Stderr = os.Stdout, os.Stderr
	var routestTerminatedCorrectly int32
	defer func() {
		if err := rCmd.Process.Kill(); err != nil {
			log.Panicf("Failed to terminate routest process: %v", err)
		} else {
			atomic.StoreInt32(&routestTerminatedCorrectly, 1)
		}
	}()
	go func() {
		err := rCmd.Run()
		if err != nil && atomic.LoadInt32(&routestTerminatedCorrectly) != 1 {
			log.Panicf("Error returned from command %+v: %v", rCmd, err)
		}
	}()
	// wait a second to give routest time to start
	// TODO do something better than waiting
	time.Sleep(time.Second)

	// run dublin-traceroute
	errCh := make(chan error, 1)

	traceFile := "trace.json"
	cl = []string{}
	if needSudo {
		cl = append([]string{"sudo"}, cl...)
	}
	executable := cppDublinTraceroutePath
	if useGoImplementation {
		executable = goDublinTraceroutePath
	}
	cl = append(cl, executable)
	if cfg.paths != nil {
		cl = append(cl, "-n", strconv.FormatInt(int64(*cfg.paths), 10))
	}
	if cfg.minTTL != nil {
		cl = append(cl, "-t", strconv.FormatInt(int64(*cfg.minTTL), 10))
	}
	if cfg.maxTTL != nil {
		cl = append(cl, "-T", strconv.FormatInt(int64(*cfg.maxTTL), 10))
	}
	if cfg.srcPort != nil {
		cl = append(cl, "-s", strconv.FormatInt(int64(*cfg.srcPort), 10))
	}
	if cfg.dstPort != nil {
		cl = append(cl, "-d", strconv.FormatInt(int64(*cfg.dstPort), 10))
	}
	if cfg.delay != nil {
		cl = append(cl, "-D", strconv.FormatInt(int64(*cfg.delay), 10))
	}
	cl = append(cl, "-o", traceFile)
	if useGoImplementation {
		a := net.ParseIP(cfg.target)
		if a == nil {
			log.Panicf("Invalid IP address: %s", cfg.target)
		}
		if a.To4() != nil {
			cl = append(cl, "--force-ipv4")
		}
	}
	cl = append(cl, cfg.target)
	log.Printf("Running %s with args %v", executable, cl[1:])
	dCmd := exec.CommandContext(ctx, cl[0], cl[1:]...)
	var outWriter bytes.Buffer
	dCmd.Stdout, dCmd.Stderr = &outWriter, os.Stderr
	go func() {
		errCh <- dCmd.Run()
	}()
	select {
	case err := <-errCh:
		if err != nil {
			return nil, nil, fmt.Errorf("failed call to dublin-traceroute: %v", err)
		}
		break
	case <-time.After(cfg.timeout):
		return nil, nil, fmt.Errorf("dublin-traceroute timed out after %s", cfg.timeout)
	}
	trace, err := ioutil.ReadFile(traceFile)
	if err != nil {
		return nil, nil, fmt.Errorf("Cannot read trace file %s: %v", traceFile, err)
	}
	return outWriter.Bytes(), trace, nil
}

func requireEqualResults(t *testing.T, got, want *results.Results) {
	for wantK, wantV := range want.Flows {
		require.Contains(t, got.Flows, wantK)
		gotV := got.Flows[wantK]
		require.Equal(t, len(wantV), len(gotV))
		for idx := 0; idx < len(wantV); idx++ {
			wantReply, gotReply := wantV[idx], gotV[idx]
			// skip FlowHash, Name, NatID
			require.Equal(t, wantReply.IsLast, gotReply.IsLast)
			// accept 20 msec of difference
			require.InDelta(t, wantReply.RttUsec, gotReply.RttUsec, 20000.)

			// match Sent packet, ignoring Timestamp, IP.SrcIP
			require.NotNil(t, gotReply.Sent, "Sent packet should be not-nil")
			require.NotNil(t, gotReply.Sent.IP, "Sent.IP should be not-nil")
			require.Equal(t, wantReply.Sent.IP.DstIP, gotReply.Sent.IP.DstIP, "Sent.IP.DstIP does not match")
			require.Equal(t, wantReply.Sent.IP.ID, gotReply.Sent.IP.ID, "Sent.IP.ID does not match")
			require.Equal(t, wantReply.Sent.IP.TTL, gotReply.Sent.IP.TTL, "Sent.IP.TTL does not match")
			require.Equal(t, wantReply.Sent.UDP, gotReply.Sent.UDP, "Sent.UDP does not match")
			// sent ICMP
			require.Nil(t, gotReply.Sent.ICMP, "Sent.ICMP should be nil")

			// match Received packet, ignoring Timestamp, IP.DstIP, IP.ID,
			// received IP must be non-nil
			require.NotNil(t, gotReply.Received, "Received should be not-nil")
			require.NotNil(t, gotReply.Received.IP, "Received.IP should be not-nil")
			require.Equal(t, wantReply.Received.IP.SrcIP, gotReply.Received.IP.SrcIP, "Received.IP.SrcIP does not match")
			// received UDP is not guaranteed to be in the response, it is safe
			// to skip this check.
			// received ICMP
			require.NotNil(t, gotReply.Received.ICMP, "Received.ICMP should not be nil")
			require.Equal(t, wantReply.Received.ICMP.Code, gotReply.Received.ICMP.Code, "Received.ICMP.Code does not match")
			require.Equal(t, wantReply.Received.ICMP.Type, gotReply.Received.ICMP.Type, "Received.ICMP.Type does not match")
			// TODO test MPLS extension

			// check for zero-ttl forwarding bug
			require.Equal(t, wantReply.ZeroTTLForwardingBug, gotReply.ZeroTTLForwardingBug, "ZeroTTLForwardingBug")
		}
	}
}

func testGoogleDNSOnePath(t *testing.T, useGoImplementation bool) {
	wantJSON, err := ioutil.ReadFile("test_data/want_8.8.8.8_one_path.json")
	require.NoError(t, err)
	c := testConfig{
		configFile: "test_data/config_8.8.8.8_one_path.json",
		paths:      &one,
		target:     "8.8.8.8",
	}
	_, gotJSON, err := runWithConfig(useGoImplementation, c)
	require.NoError(t, err)
	var want, got results.Results
	err = json.Unmarshal(wantJSON, &want)
	require.NoError(t, err)
	err = json.Unmarshal(gotJSON, &got)
	require.NoError(t, err)
	require.Equal(t, len(want.Flows), len(got.Flows))
	requireEqualResults(t, &got, &want)
}

func TestGoogleDNSOnePathCPP(t *testing.T) {
	testGoogleDNSOnePath(t, false)
}

func TestGoogleDNSOnePathGo(t *testing.T) {
	testGoogleDNSOnePath(t, true)
}
