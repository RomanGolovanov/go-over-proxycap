package go-over-proxycap

import "encoding/xml"

// RuleSet element
type RuleSet struct {
	XMLName      xml.Name      `xml:"proxycap_ruleset"`
	Version      uint          `xml:"version,attr"`
	ProxyServers []ProxyServer `xml:"proxy_servers>proxy_server"`
	ProxyChains  []ProxyChain  `xml:"proxy_chains>proxy_chain"`
	RoutingRules []RoutingRule `xml:"routing_rules>routing_rule"`
}

// ProxyServer element
type ProxyServer struct {
	Name              string `xml:"name,attr"`
	Type              string `xml:"type,attr"`
	HostName          string `xml:"hostname,attr"`
	Port              uint   `xml:"port,attr"`
	AuthMethod        string `xml:"auth_method,attr"`
	PrefferedCipher   string `xml:"pref_cipher,attr,omitempty"`
	ShadowSocksCipher string `xml:"ss_cipher,attr,omitempty"`
	Default           bool   `xml:"is_default,attr"`
	UserName          string `xml:"username,attr,omitempty"`
	Password          string `xml:"password,attr,omitempty"`
	Key               string `xml:"key,attr,omitempty"`
	HostKey           string `xml:"hostkey,attr,omitempty"`
}

// NamedRef element
type NamedRef struct {
	Name string `xml:"name,attr"`
}

// ProxyChain element
type ProxyChain struct {
	Name    string     `xml:"name,attr"`
	Servers []NamedRef `xml:"proxy_server"`
}

// RoutingRule element
type RoutingRule struct {
	Name                string          `xml:"name,attr"`
	Action              string          `xml:"action,attr"`
	RemoteDNS           bool            `xml:"remote_dns,attr"`
	Disabled            bool            `xml:"disabled,attr"`
	Transports          string          `xml:"transports,attr"`
	ProxiesOrChains     []NamedRef      `xml:"proxy_or_chain"`
	Programs            []Program       `xml:"programs>program"`
	PortRanges          []PortRange     `xml:"ports>port_range"`
	IPRanges            []IPRange       `xml:"ip_addresses>ip_range"`
	HostNames           []HostNameRange `xml:"hostnames>hostname"`
	RemoteDNSExceptions []HostNameRange `xml:"remote_dns_exceptions>remote_dns_exception"`
}

// Program element
type Program struct {
	Path        string `xml:"path,attr"`
	DirIncluded bool   `xml:"dir_included,attr"`
}

// IPRange element
type IPRange struct {
	IP   string `xml:"ip,attr"`
	Mask uint   `xml:"mask,attr"`
}

// PortRange element
type PortRange struct {
	First uint `xml:"first,attr"`
	Last  uint `xml:"last,attr"`
}

// HostNameRange element
type HostNameRange struct {
	Wildcard string `xml:"wildcard,attr"`
}

// DefaultVersion for RuleSet
const DefaultVersion = 535

// Rule transports
const (
	TransportTCP = "tcp"
	TransportUDP = "udp"
	TransportAll = "all"
)

// Rule actions
const (
	ActionDirect = "direct"
	ActionProxy  = "proxy"
	ActionBlock  = "block"
)

// Proxy types
const (
	ProxyTypeHTTP        = "http"
	ProxyTypeHTTPS       = "https"
	ProxyTypeShadowSocks = "shadowsocks"
	ProxyTypeSocks4      = "socks4"
	ProxyTypeSocks5      = "socks5"
	ProxyTypeSSH         = "ssh"
)

// Authentication methods
const (
	AuthenticationMethodNone       = "none"
	AuthenticationMethodPassword   = "password"
	AuthenticationMethodIntegrated = "integrated"
	AuthenticationMethodGssAPI     = "gssapi"
	AuthenticationMethodKey        = "key"
)

// Ciphers suites
var Ciphers = []string{
	"aes128-ctr",
	"aes192-ctr",
	"aes256-ctr",
	"aes128-gcm@openssh.com",
	"aes256-gcm@openssh.com",
	"arcfour256",
	"arcfour128",
	"aes128-cbc",
	"3des-cbc",
	"blowfish-cbc",
	"cast128-cbc",
	"aes192-cbc",
	"aes256-cbc",
	"arcfour",
}

// ShadowSocksCiphers suites
var ShadowSocksCiphers = []string{
	"rc4",
	"rc4-md5",
	"aes-128-cfb",
	"aes-192-cfb",
	"aes-256-cfb",
	"aes-128-ctr",
	"aes-192-ctr",
	"aes-256-ctr",
	"bf-cfb",
	"camellia-128-cfb",
	"camellia-192-cfb",
	"camellia-256-cfb",
	"aes-128-gcm",
	"aes-192-gcm",
	"aes-256-gcm",
	"chacha20-ietf-poly1305",
}
