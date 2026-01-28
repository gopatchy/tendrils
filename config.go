package tendrils

import (
	"encoding/json"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Locations []*Location `yaml:"locations" json:"locations"`
}

type Location struct {
	Name      string      `yaml:"name" json:"name"`
	Direction string      `yaml:"direction,omitempty" json:"direction,omitempty"`
	Nodes     []string    `yaml:"nodes,omitempty" json:"nodes,omitempty"`
	Children  []*Location `yaml:"children,omitempty" json:"children,omitempty"`
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
