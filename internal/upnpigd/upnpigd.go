package upnpigd

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const ssdpAddr = "239.255.255.250:1900"

type Client struct {
	ControlURL  string
	ServiceType string
	LocalIP     net.IP
	HTTPClient  *http.Client
}

type Mapping struct {
	InternalPort int
	ExternalPort int
	Protocol     string
	Lifetime     time.Duration
}

func Discover(ctx context.Context) (*Client, error) {
	location, err := discoverLocation(ctx)
	if err != nil {
		return nil, err
	}
	controlURL, serviceType, err := fetchControlURL(ctx, location)
	if err != nil {
		return nil, err
	}
	localIP, err := localIPFor(location)
	if err != nil {
		return nil, err
	}
	return &Client{
		ControlURL:  controlURL,
		ServiceType: serviceType,
		LocalIP:     localIP,
		HTTPClient:  &http.Client{Timeout: 5 * time.Second},
	}, nil
}

func (c *Client) PublicAddress(ctx context.Context) (net.IP, error) {
	body, err := c.soap(ctx, "GetExternalIPAddress", nil)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Body struct {
			Response struct {
				NewExternalIPAddress string `xml:"NewExternalIPAddress"`
			} `xml:"GetExternalIPAddressResponse"`
		} `xml:"Body"`
	}
	if err := xml.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	ip := net.ParseIP(strings.TrimSpace(resp.Body.Response.NewExternalIPAddress))
	if ip == nil {
		return nil, fmt.Errorf("bad UPnP external address response")
	}
	return ip, nil
}

func (c *Client) MapTCP(ctx context.Context, internalPort, externalPort int, lifetime time.Duration, description string) (Mapping, error) {
	if internalPort <= 0 || internalPort > 65535 || externalPort <= 0 || externalPort > 65535 {
		return Mapping{}, fmt.Errorf("invalid TCP mapping %d->%d", internalPort, externalPort)
	}
	if c.LocalIP == nil {
		return Mapping{}, errors.New("UPnP local IP is not set")
	}
	if lifetime <= 0 {
		lifetime = time.Hour
	}
	if description == "" {
		description = "macftpd"
	}
	args := map[string]string{
		"NewRemoteHost":             "",
		"NewExternalPort":           strconv.Itoa(externalPort),
		"NewProtocol":               "TCP",
		"NewInternalPort":           strconv.Itoa(internalPort),
		"NewInternalClient":         c.LocalIP.String(),
		"NewEnabled":                "1",
		"NewPortMappingDescription": description,
		"NewLeaseDuration":          strconv.Itoa(int(lifetime.Seconds())),
	}
	if _, err := c.soap(ctx, "AddPortMapping", args); err != nil {
		return Mapping{}, err
	}
	return Mapping{InternalPort: internalPort, ExternalPort: externalPort, Protocol: "TCP", Lifetime: lifetime}, nil
}

func (c *Client) DeleteTCP(ctx context.Context, externalPort int) error {
	if externalPort <= 0 || externalPort > 65535 {
		return fmt.Errorf("invalid TCP external port %d", externalPort)
	}
	args := map[string]string{
		"NewRemoteHost":   "",
		"NewExternalPort": strconv.Itoa(externalPort),
		"NewProtocol":     "TCP",
	}
	_, err := c.soap(ctx, "DeletePortMapping", args)
	return err
}

func (c *Client) soap(ctx context.Context, action string, args map[string]string) ([]byte, error) {
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0"?>`)
	b.WriteString(`<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">`)
	b.WriteString(`<s:Body>`)
	fmt.Fprintf(&b, `<u:%s xmlns:u="%s">`, action, xmlEscape(c.ServiceType))
	for name, value := range args {
		fmt.Fprintf(&b, `<%s>%s</%s>`, name, xmlEscape(value), name)
	}
	fmt.Fprintf(&b, `</u:%s>`, action)
	b.WriteString(`</s:Body></s:Envelope>`)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ControlURL, bytes.NewBufferString(b.String()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
	req.Header.Set("SOAPAction", fmt.Sprintf(`"%s#%s"`, c.ServiceType, action))
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("UPnP %s failed: %s: %s", action, resp.Status, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func discoverLocation(ctx context.Context) (string, error) {
	conn, err := net.ListenPacket("udp4", ":0")
	if err != nil {
		return "", err
	}
	defer conn.Close()
	deadline := time.Now().Add(3 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)
	msg := strings.Join([]string{
		"M-SEARCH * HTTP/1.1",
		"HOST: " + ssdpAddr,
		`MAN: "ssdp:discover"`,
		"MX: 2",
		"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		"", "",
	}, "\r\n")
	addr, err := net.ResolveUDPAddr("udp4", ssdpAddr)
	if err != nil {
		return "", err
	}
	if _, err := conn.WriteTo([]byte(msg), addr); err != nil {
		return "", err
	}
	buf := make([]byte, 64*1024)
	for {
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			return "", err
		}
		location := headerValue(string(buf[:n]), "location")
		if location != "" {
			return location, nil
		}
	}
}

func fetchControlURL(ctx context.Context, location string) (string, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, location, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", "", fmt.Errorf("UPnP root description failed: %s", resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return "", "", err
	}
	control, serviceType, err := parseRootDescription(raw)
	if err != nil {
		return "", "", err
	}
	base, err := url.Parse(location)
	if err != nil {
		return "", "", err
	}
	ref, err := url.Parse(control)
	if err != nil {
		return "", "", err
	}
	return base.ResolveReference(ref).String(), serviceType, nil
}

func localIPFor(location string) (net.IP, error) {
	u, err := url.Parse(location)
	if err != nil {
		return nil, err
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("UPnP location has no host")
	}
	conn, err := net.DialTimeout("udp4", net.JoinHostPort(host, "1900"), 2*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok || addr.IP == nil {
		return nil, errors.New("cannot determine local UPnP client IP")
	}
	return addr.IP, nil
}

func parseRootDescription(raw []byte) (string, string, error) {
	var root rootDesc
	if err := xml.Unmarshal(raw, &root); err != nil {
		return "", "", err
	}
	if svc := findWANService(root.Device); svc != nil {
		return strings.TrimSpace(svc.ControlURL), strings.TrimSpace(svc.ServiceType), nil
	}
	return "", "", errors.New("UPnP WAN connection service not found")
}

func findWANService(device deviceDesc) *serviceDesc {
	for _, svc := range device.ServiceList.Services {
		serviceType := strings.ToLower(svc.ServiceType)
		if strings.Contains(serviceType, "wanipconnection") || strings.Contains(serviceType, "wanpppconnection") {
			return &svc
		}
	}
	for _, child := range device.DeviceList.Devices {
		if svc := findWANService(child); svc != nil {
			return svc
		}
	}
	return nil
}

func headerValue(raw, key string) string {
	key = strings.ToLower(key)
	for _, line := range strings.Split(raw, "\n") {
		name, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if strings.ToLower(strings.TrimSpace(name)) == key {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func xmlEscape(value string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(value))
	return b.String()
}

type rootDesc struct {
	Device deviceDesc `xml:"device"`
}

type deviceDesc struct {
	ServiceList serviceListDesc `xml:"serviceList"`
	DeviceList  deviceListDesc  `xml:"deviceList"`
}

type serviceListDesc struct {
	Services []serviceDesc `xml:"service"`
}

type deviceListDesc struct {
	Devices []deviceDesc `xml:"device"`
}

type serviceDesc struct {
	ServiceType string `xml:"serviceType"`
	ControlURL  string `xml:"controlURL"`
}
