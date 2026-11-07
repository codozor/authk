package main

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/codozor/authk/internal/config"
	"github.com/spf13/cobra"
)

var (
	migrateDryRun bool
	migrateForce  bool
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage the configuration file",
}

var configMigrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Rewrite a version 1 config file in the version 2 format",
	Long: `Rewrite the config file in the version 2 format, with a single "default" profile.
Version 1 files keep working without migration: they are converted in memory.

The original file is kept as <file>.v1.bak. Comments are not kept. Secret
references (ref+env://, ref+sops://, ...) are written as they are, never resolved.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		if cfg.SourceVersion() >= config.CurrentVersion && !migrateForce {
			_, err := fmt.Fprintf(out, "%s is already in version %d format\n", cfg.Path(), config.CurrentVersion)
			return err
		}

		rendered, err := config.Render(cfg)
		if err != nil {
			return err
		}
		if migrateDryRun {
			_, err := out.Write(rendered)
			return err
		}

		backup := fmt.Sprintf("%s.v%d.bak", cfg.Path(), cfg.SourceVersion())
		if _, err := os.Stat(backup); err == nil && !migrateForce {
			return fmt.Errorf("backup %s already exists: remove it or use --force", backup)
		}
		if err := migrateFile(cfg.Path(), backup, rendered); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "Migrated %s to version %d (backup: %s)\nComments of the original file were not kept.\n",
			cfg.Path(), config.CurrentVersion, backup)
		return err
	},
}

// migrateFile copies path to backup, then replaces path with content atomically,
// keeping its permissions.
func migrateFile(path, backup string, content []byte) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := os.WriteFile(backup, original, info.Mode().Perm()); err != nil {
		return fmt.Errorf("failed to write backup: %w", err)
	}

	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".migrate-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(content); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Chmod(info.Mode().Perm()); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		_ = os.Remove(tmp.Name())
		return fmt.Errorf("failed to replace config file: %w", err)
	}
	return nil
}

var configProfilesCmd = &cobra.Command{
	Use:   "profiles",
	Short: "List the profiles of the config file",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		selected, _ := cfg.ProfileName(profileFlag())

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
		_, _ = fmt.Fprintln(w, "\tPROFILE\tFLOW\tCLIENT\tISSUER")
		for _, name := range cfg.ProfileNames() {
			p := cfg.Profiles[name]
			mark := ""
			if name == selected {
				mark = "*"
			}
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", mark, name, p.Flow.Type, p.ClientID, p.IssuerURL)
		}
		if err := w.Flush(); err != nil {
			return err
		}
		if cfg.SourceVersion() < config.CurrentVersion {
			_, err = fmt.Fprintf(cmd.ErrOrStderr(), "\n%s is a version %d file: \"authk config migrate\" rewrites it in version %d format.\n",
				cfg.Path(), cfg.SourceVersion(), config.CurrentVersion)
		}
		return err
	},
}

func init() {
	configMigrateCmd.Flags().BoolVar(&migrateDryRun, "dry-run", false, "Print the migrated file instead of writing it")
	configMigrateCmd.Flags().BoolVar(&migrateForce, "force", false, "Overwrite an existing backup, or rewrite a version 2 file")
	configCmd.AddCommand(configMigrateCmd, configProfilesCmd)
	rootCmd.AddCommand(configCmd)
}
