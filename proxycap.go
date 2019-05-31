package proxycap

import "encoding/xml"

// See documentation on http://www.proxycap.com/xml2prs-format.html

// RuleSet element
type RuleSet struct {
	XMLName      xml.Name      `xml:"proxycap_ruleset"`
	Version      uint          `xml:"version,attr"`
	ProxyServers []ProxyServer `xml:"proxy_servers>proxy_server"`
	ProxyChains  []ProxyChain  `xml:"proxy_chains>proxy_chain,omitempty"`
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
	Name                string                   `xml:"name,attr"`
	Action              string                   `xml:"action,attr"`
	RemoteDNS           bool                     `xml:"remote_dns,attr"`
	Disabled            bool                     `xml:"disabled,attr"`
	Transports          string                   `xml:"transports,attr"`
	ProxiesOrChains     []NamedRef               `xml:"proxy_or_chain,omitempty"`
	Programs            *ProgramColl             `xml:"programs,omitempty"`
	PortRanges          *PortRangeColl           `xml:"ports,omitempty"`
	IPRanges            *IPRangeColl             `xml:"ip_addresses,omitempty"`
	HostNames           *HostNameRangeColl       `xml:"hostnames,omitempty"`
	RemoteDNSExceptions *RemoteDNSExceptionsColl `xml:"remote_dns_exceptions,omitempty"`
}

// ProgramColl element
type ProgramColl struct {
	Programs []Program `xml:"program,omitempty"`
}

// Program element
type Program struct {
	Path        string `xml:"path,attr"`
	DirIncluded bool   `xml:"dir_included,attr"`
}

// IPRangeColl element
type IPRangeColl struct {
	IPRanges []IPRange `xml:"ip_range,omitempty"`
}

// IPRange element
type IPRange struct {
	IP   string `xml:"ip,attr"`
	Mask uint   `xml:"mask,attr"`
}

// PortRangeColl element
type PortRangeColl struct {
	PortRanges []PortRange `xml:"port_range,omitempty"`
}

// PortRange element
type PortRange struct {
	First uint `xml:"first,attr"`
	Last  uint `xml:"last,attr"`
}

// HostNameRangeColl element
type HostNameRangeColl struct {
	HostNameRanges []HostWildcard `xml:"hostname,omitempty"`
}

// RemoteDNSExceptionsColl element
type RemoteDNSExceptionsColl struct {
	RemoteDNSExceptions []HostWildcard `xml:"remote_dns_exception,omitempty"`
}

// HostWildcard element
type HostWildcard struct {
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
