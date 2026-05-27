package upnpigd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseRootDescriptionFindsNestedWANIPConnection(t *testing.T) {
	raw := []byte(`<?xml version="1.0"?>
<root>
  <device>
    <deviceList>
      <device>
        <deviceList>
          <device>
            <serviceList>
              <service>
                <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
                <controlURL>/ctl/IPConn</controlURL>
              </service>
            </serviceList>
          </device>
        </deviceList>
      </device>
    </deviceList>
  </device>
</root>`)
	controlURL, serviceType, err := parseRootDescription(raw)
	if err != nil {
		t.Fatal(err)
	}
	if controlURL != "/ctl/IPConn" {
		t.Fatalf("unexpected control URL: %q", controlURL)
	}
	if serviceType != "urn:schemas-upnp-org:service:WANIPConnection:1" {
		t.Fatalf("unexpected service type: %q", serviceType)
	}
}

func TestHeaderValueIsCaseInsensitive(t *testing.T) {
	raw := "HTTP/1.1 200 OK\r\nLOCATION: http://192.168.0.1/rootDesc.xml\r\n\r\n"
	if got := headerValue(raw, "location"); got != "http://192.168.0.1/rootDesc.xml" {
		t.Fatalf("unexpected location: %q", got)
	}
}

func TestDeleteTCPUsesDeletePortMapping(t *testing.T) {
	var body string
	var soapAction string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		body = string(raw)
		soapAction = r.Header.Get("SOAPAction")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`<s:Envelope><s:Body></s:Body></s:Envelope>`))
	}))
	defer ts.Close()

	client := &Client{
		ControlURL:  ts.URL,
		ServiceType: "urn:schemas-upnp-org:service:WANIPConnection:2",
		HTTPClient:  ts.Client(),
	}
	if err := client.DeleteTCP(t.Context(), 50006); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(soapAction, "#DeletePortMapping") {
		t.Fatalf("unexpected SOAPAction: %q", soapAction)
	}
	for _, want := range []string{"<u:DeletePortMapping", "<NewExternalPort>50006</NewExternalPort>", "<NewProtocol>TCP</NewProtocol>"} {
		if !strings.Contains(body, want) {
			t.Fatalf("SOAP body missing %q: %s", want, body)
		}
	}
}
