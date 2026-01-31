package tendrils

import (
	"encoding/json"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Locations   []*Location `yaml:"locations" json:"locations"`
	SharedNames []string    `yaml:"shared_names,omitempty" json:"shared_names,omitempty"`
}

type Location struct {
	Name      string        `yaml:"name" json:"name"`
	Direction string        `yaml:"direction,omitempty" json:"direction,omitempty"`
	Nodes     []*NodeConfig `yaml:"nodes,omitempty" json:"nodes,omitempty"`
	Children  []*Location   `yaml:"children,omitempty" json:"children,omitempty"`
}

type NodeConfig struct {
	Names []string `yaml:"names,omitempty" json:"names,omitempty"`
	MACs  []string `yaml:"macs,omitempty" json:"macs,omitempty"`
	IPs   []string `yaml:"ips,omitempty" json:"ips,omitempty"`
	Avoid bool     `yaml:"avoid,omitempty" json:"avoid,omitempty"`
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

func (c *Config) AllNodeConfigs() []*NodeConfig {
	var result []*NodeConfig
	var visit func([]*Location)
	visit = func(locs []*Location) {
		for _, loc := range locs {
			result = append(result, loc.Nodes...)
			visit(loc.Children)
		}
	}
	visit(c.Locations)
	return result
}
