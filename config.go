package wgsd

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"net"
	"os"
)

type Config struct {
	PersistentPeers map[string]struct{} `yaml:"persistent_peers"`
	PeerRoutes      map[string]Route    `yaml:"peer_routes"`
}

type Route struct {
	Name       string      `yaml:"name"`
	AllowedIPs []net.IPNet `yaml:"allowed_ips"`
}

var (
	ClientConfig Config
)

func Parse() {
	appEnv := os.Getenv("APP_ENV")
	if appEnv == "" {
		appEnv = "dev"
	}
	fileName := "conf/config." + appEnv + ".yaml"
	file, err := ioutil.ReadFile(fileName)
	if err != nil {
		panic(err)
	}

	err = yaml.Unmarshal(file, &ClientConfig)
	if err != nil {
		panic(err)
	}
}
