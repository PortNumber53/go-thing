package utility

import (
	"os"
	"strings"
	"sync"

	"go-thing/internal/config"
	"gopkg.in/ini.v1"
)

var (
	configOnce       sync.Once
	configData       map[string]string
	configErr        error
	dockerAutoRemove bool
	chrootDirOnce    sync.Once
	chrootDirCached  string
)

// LoadConfig reads the INI config at config.ConfigFilePath and caches values.
func LoadConfig() (map[string]string, error) {
	configOnce.Do(func() {
		path := os.ExpandEnv(config.ConfigFilePath)
		cfg, err := ini.Load(path)
		if err != nil {
			configErr = err
			return
		}
		// Load from [default] section
		defaultSection := cfg.Section("default")
		configData = make(map[string]string)
		for _, key := range defaultSection.Keys() {
			configData[key.Name()] = key.String()
		}
		dockerAutoRemove = strings.EqualFold(cfg.Section("default").Key("DOCKER_AUTO_REMOVE").String(), "true")
	})
	return configData, configErr
}

// GetChrootDir returns the CHROOT_DIR from config if set, else empty string.
func GetChrootDir() string {
	chrootDirOnce.Do(func() {
		cfg, err := LoadConfig()
		if err != nil {
			chrootDirCached = ""
			return
		}
		chrootDirCached = strings.TrimRight(strings.TrimSpace(cfg["CHROOT_DIR"]), "/")
	})
	return chrootDirCached
}

// DockerAutoRemove returns the cached DOCKER_AUTO_REMOVE flag.
func DockerAutoRemove() bool {
	// ensure config was at least attempted to be loaded
	_, _ = LoadConfig()
	return dockerAutoRemove
}
