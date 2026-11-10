package agent

import (
	"path/filepath"
	"strings"
)

// Name returns the readable name of an agent, built from what identifies it:
//
//   - the directory of the config file ("~" for a config in the home directory);
//   - "/<profile>", except for the "default" profile (version 1 configs);
//   - "@<dir>" when the agent writes a project .env (envFile, empty otherwise) that is
//     not next to the config, relative to the config directory when possible.
//
// For example app/dev, other, legacy@front, ~@dev/project. Paths must be canonical.
// Names are not unique: two projects with the same directory name give the same name,
// and commands then ask for the agent ID.
func Name(configPath, profile, envFile, home string) string {
	configDir := filepath.Dir(configPath)
	name := filepath.Base(configDir)
	if home != "" && configDir == filepath.Clean(home) {
		name = "~"
	}
	if profile != "" && profile != "default" {
		name += "/" + profile
	}
	if envFile != "" {
		if envDir := filepath.Dir(envFile); envDir != configDir {
			rel, err := filepath.Rel(configDir, envDir)
			if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				rel = filepath.Base(envDir)
			}
			name += "@" + filepath.ToSlash(rel)
		}
	}
	return name
}
