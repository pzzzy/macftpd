package natpmp

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPort = "5351"
	opAddress   = 0
	opMapTCP    = 2
	resultOK    = 0
)

type Client struct {
	Gateway string
	Timeout time.Duration
}

type Mapping struct {
	InternalPort int
	ExternalPort int
	Lifetime     time.Duration
}

func DiscoverGateway() (string, error) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return "", err
	}
	re := regexp.MustCompile(`(?m)^\s*gateway:\s*(\S+)`)
	match := re.FindStringSubmatch(string(out))
	if len(match) != 2 {
		return "", errors.New("default gateway not found")
	}
	return match[1], nil
}

func (c Client) PublicAddress(ctx context.Context) (net.IP, error) {
	resp, err := c.roundTrip(ctx, []byte{0, opAddress})
	if err != nil {
		return nil, err
	}
	if len(resp) < 12 || resp[1] != 128+opAddress {
		return nil, fmt.Errorf("bad NAT-PMP public address response")
	}
	if result := binary.BigEndian.Uint16(resp[2:4]); result != resultOK {
		return nil, fmt.Errorf("NAT-PMP public address result=%d", result)
	}
	return net.IPv4(resp[8], resp[9], resp[10], resp[11]), nil
}

func (c Client) MapTCP(ctx context.Context, internalPort, externalPort int, lifetime time.Duration) (Mapping, error) {
	if internalPort <= 0 || internalPort > 65535 || externalPort <= 0 || externalPort > 65535 {
		return Mapping{}, fmt.Errorf("invalid TCP mapping %d->%d", internalPort, externalPort)
	}
	seconds := uint32(lifetime.Seconds())
	req := make([]byte, 12)
	req[0] = 0
	req[1] = opMapTCP
	binary.BigEndian.PutUint16(req[4:6], uint16(internalPort))
	binary.BigEndian.PutUint16(req[6:8], uint16(externalPort))
	binary.BigEndian.PutUint32(req[8:12], seconds)
	resp, err := c.roundTrip(ctx, req)
	if err != nil {
		return Mapping{}, err
	}
	if len(resp) < 16 || resp[1] != 128+opMapTCP {
		return Mapping{}, fmt.Errorf("bad NAT-PMP TCP mapping response")
	}
	if result := binary.BigEndian.Uint16(resp[2:4]); result != resultOK {
		return Mapping{}, fmt.Errorf("NAT-PMP TCP mapping result=%d", result)
	}
	return Mapping{
		InternalPort: int(binary.BigEndian.Uint16(resp[8:10])),
		ExternalPort: int(binary.BigEndian.Uint16(resp[10:12])),
		Lifetime:     time.Duration(binary.BigEndian.Uint32(resp[12:16])) * time.Second,
	}, nil
}

func MaintainTCP(ctx context.Context, gateway string, ports []int, lifetime time.Duration, setExternalIP func(string)) {
	if gateway == "" {
		discovered, err := DiscoverGateway()
		if err != nil {
			log.Printf("natpmp: gateway discovery failed: %v", err)
			return
		}
		gateway = discovered
	}
	if lifetime <= 0 {
		lifetime = time.Hour
	}
	client := Client{Gateway: gateway, Timeout: 2 * time.Second}
	for {
		renewEvery := lifetime / 2
		if renewEvery < 5*time.Minute {
			renewEvery = 5 * time.Minute
		}
		attemptCtx, cancel := context.WithTimeout(ctx, time.Duration(len(ports)+2)*client.Timeout)
		ip, err := client.PublicAddress(attemptCtx)
		if err != nil {
			log.Printf("natpmp: public address failed via %s: %v", gateway, err)
		} else {
			setExternalIP(ip.String())
			log.Printf("natpmp: public address %s via %s", ip, gateway)
		}
		var mapped, mismatched int
		hadFailure := err != nil
		for _, port := range ports {
			mapping, err := client.MapTCP(attemptCtx, port, port, lifetime)
			if err != nil {
				hadFailure = true
				log.Printf("natpmp: map tcp %d failed: %v", port, err)
				continue
			}
			if mapping.ExternalPort != port {
				mismatched++
				log.Printf("natpmp: tcp %d mapped to external %d, classic PASV requires matching ports", port, mapping.ExternalPort)
				continue
			}
			mapped++
		}
		cancel()
		log.Printf("natpmp: mapped %d tcp ports, %d mismatched", mapped, mismatched)
		if hadFailure || mapped < len(ports) {
			renewEvery = 30 * time.Second
		}
		timer := time.NewTimer(renewEvery)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

func (c Client) roundTrip(ctx context.Context, payload []byte) ([]byte, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 2 * time.Second
	}
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "udp", net.JoinHostPort(c.Gateway, defaultPort))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func ParsePorts(spec string) []int {
	var ports []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			a, b, _ := strings.Cut(part, "-")
			start, errA := strconv.Atoi(strings.TrimSpace(a))
			end, errB := strconv.Atoi(strings.TrimSpace(b))
			if errA != nil || errB != nil || start > end {
				continue
			}
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
			continue
		}
		port, err := strconv.Atoi(part)
		if err == nil {
			ports = append(ports, port)
		}
	}
	return ports
}
