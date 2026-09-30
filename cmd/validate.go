/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os"

	"github.com/daeuniverse/dae/config"
	"github.com/daeuniverse/dae/control"
	"github.com/spf13/cobra"
)

var (
	validateCmd = &cobra.Command{
		Use:   "validate",
		Short: "To validate dae config.",
		Run: func(cmd *cobra.Command, args []string) {
			if cfgFile == "" {
				fmt.Println("Argument \"--config\" or \"-c\" is required but not provided.")
				os.Exit(1)
			}
			// Read config from --config cfgFile.
			conf, _, err := readConfig(cfgFile)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			if err := validateFixedDomainTtl(conf); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		},
	}
)

// validateFixedDomainTtl dry-runs the only consumer-side parsing of the
// dns.fixed_domain_ttl section. ParseFixedDomainTtl executes in ControlPlane
// construction, not in config loading, so without this check `dae validate`
// exits 0 while the daemon fails at start on a bad TTL — breaking the
// invariant that a passing validate means a starting daemon.
// (Parity with dae main 5a5473d5.)
func validateFixedDomainTtl(conf *config.Config) error {
	_, err := control.ParseFixedDomainTtl(conf.Dns.FixedDomainTtl)
	return err
}

func init() {
	rootCmd.AddCommand(validateCmd)

	validateCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file")
}
