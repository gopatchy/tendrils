package tendrils

import (
	"encoding/json"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Locations []*Location `yaml:"locations" json:"locations"`
}

type Location struct {
	Name      string       `yaml:"name" json:"name"`
	Direction string       `yaml:"direction,omitempty" json:"direction,omitempty"`
	Nodes     []*NodeRef   `yaml:"nodes,omitempty" json:"nodes,omitempty"`
	Children  []*Location  `yaml:"children,omitempty" json:"children,omitempty"`
}

type NodeRef struct {
	Name string `yaml:"name,omitempty" json:"name,omitempty"`
	MAC  string `yaml:"mac,omitempty" json:"mac,omitempty"`
	IP   string `yaml:"ip,omitempty" json:"ip,omitempty"`
}

func (r *NodeRef) DisplayName() string {
	if r.Name != "" {
		return r.Name
	}
	if r.MAC != "" {
		return r.MAC
	}
	return r.IP
}

func (r *NodeRef) ParseMAC() net.HardwareAddr {
	if r.MAC == "" {
		return nil
	}
	mac, _ := net.ParseMAC(r.MAC)
	return mac
}

func (r *NodeRef) ParseIP() net.IP {
	if r.IP == "" {
		return nil
	}
	return net.ParseIP(r.IP)
}

func (c *Config) AllNodeRefs() []*NodeRef {
	var refs []*NodeRef
	var collect func([]*Location)
	collect = func(locs []*Location) {
		for _, loc := range locs {
			refs = append(refs, loc.Nodes...)
			collect(loc.Children)
		}
	}
	collect(c.Locations)
	return refs
}

func LoadConfig(path string) (*Config, error) {
	if path == "" {
		return &Config{}, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}
