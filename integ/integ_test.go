package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/build"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"strconv"
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
	needSudo = true

	defaultDubTrTimeout = 10 * time.Second
)

// isCI returns true if the environment is a CI like Travis-CI or CircleCI,
// false otherwise.
func isCI() bool {
	return os.Getenv("CI") == "true"
}

func setup() {
	if isCI() {
		cl := []string{"iptables", "-A", "OUTPUT", "-p", "udp", "--dport", "33434:33634", "-d", "8.8.8.8", "-j", "NFQUEUE", "--queue-num", strconv.FormatInt(NfQueueNum, 10)}
		if needSudo {
			cl = append([]string{"sudo"}, cl...)
		}
		if err := exec.Command(cl[0], cl[1:]...).Run(); err != nil {
			log.Panicf("Failed to run iptables: %v", err)
		}
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

func runWithConfig(cfg testConfig) ([]byte, []byte, error) {
	// validate to config
	if cfg.timeout <= 0 {
		cfg.timeout = defaultDubTrTimeout
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// run routest
	riCmd := exec.Command("go", "install", "github.com/insomniacslk/dublin-traceroute/go/dublintraceroute/cmd/routest")
	riCmd.Stdout, riCmd.Stderr = os.Stdout, os.Stderr
	if err := riCmd.Run(); err != nil {
		return nil, nil, fmt.Errorf("Cannot install routest: %v", err)
	}
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		gopath = build.Default.GOPATH
	}
	cl := []string{path.Join(gopath, "bin/routest"), "-i", "lo", "-c", cfg.configFile, "-q", strconv.FormatInt(NfQueueNum, 10)}
	if needSudo {
		cl = append([]string{"sudo"}, cl...)
	}
	rCmd := exec.CommandContext(ctx, cl[0], cl[1:]...)
	rCmd.Stdout, rCmd.Stderr = os.Stdout, os.Stderr
	defer func() {
		_ = rCmd.Process.Kill()
	}()
	go func() {
		if err := rCmd.Run(); err != nil {
			log.Printf("Error returned from command %+v: %v", rCmd, err)
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
	cl = append(cl, "../build/dublin-traceroute")
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
	cl = append(cl, cfg.target)
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
			require.NotNil(t, gotReply.Sent, "Sent is nil")
			require.NotNil(t, gotReply.Sent.IP, "Sent.IP not nil")
			require.Equal(t, wantReply.Sent.IP.DstIP, gotReply.Sent.IP.DstIP, "Sent.IP.DstIP")
			require.Equal(t, wantReply.Sent.IP.ID, gotReply.Sent.IP.ID, "Sent.IP.ID")
			require.Equal(t, wantReply.Sent.IP.TTL, gotReply.Sent.IP.TTL, "Sent.IP.TTL")
			require.Equal(t, wantReply.Sent.UDP, gotReply.Sent.UDP, "Sent.UDP")
			// ICMP should be nil
			require.Nil(t, gotReply.Sent.ICMP, "Sent.ICMP not nil")
			// match Received packet, ignoring Timestamp, IP.DstIP, IP.ID,
			// IP.TTL
			require.NotNil(t, gotReply.Received, "Received is nil")
			require.NotNil(t, gotReply.Received.IP, "Received.IP is nil")
			require.Equal(t, wantReply.Received.IP.SrcIP, gotReply.Received.IP.SrcIP, "Received.IP.SrcIP")
			// UDP should be nil
			require.Equal(t, wantReply.Received.UDP, gotReply.Received.UDP, "Received.UDP")
			require.Nil(t, gotReply.Received.UDP, "Received.UDP is not nil")
			require.Equal(t, wantReply.Received.ICMP, gotReply.Received.ICMP, "Received.ICMP")
			require.Equal(t, wantReply.ZeroTTLForwardingBug, gotReply.ZeroTTLForwardingBug, "ZeroTTLForwardingBug")
		}
	}
}

func TestGoogleDNSOnePath(t *testing.T) {
	wantJSON, err := ioutil.ReadFile("test_data/want_8.8.8.8_one_path.json")
	require.NoError(t, err)
	c := testConfig{
		configFile: "test_data/config_8.8.8.8_one_path.json",
		paths:      &one,
		target:     "8.8.8.8",
	}
	_, gotJSON, err := runWithConfig(c)
	require.NoError(t, err)
	var want, got results.Results
	err = json.Unmarshal(wantJSON, &want)
	require.NoError(t, err)
	err = json.Unmarshal(gotJSON, &got)
	require.NoError(t, err)
	require.Equal(t, len(want.Flows), len(got.Flows))
	requireEqualResults(t, &got, &want)
}
