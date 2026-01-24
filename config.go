package tendrils

import (
	"encoding/json"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Locations map[string]*Location `yaml:"locations" json:"locations"`
}

type Location struct {
	Nodes    []string             `yaml:"nodes,omitempty" json:"nodes,omitempty"`
	Children map[string]*Location `yaml:"children,omitempty" json:"children,omitempty"`
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
