/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package cmd

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/daeuniverse/dae/cmd/internal"
	"github.com/daeuniverse/dae/common/consts"
	"github.com/spf13/cobra"
)

var (
	updateRoutingCmd = &cobra.Command{
		Use:     "routing [pid]",
		Aliases: []string{"update-routing"},
		Short:   "Apply routing rule changes without full reload.",
		Run: func(cmd *cobra.Command, args []string) {
			internal.AutoSu()

			// Determine PID.
			if len(args) == 0 {
				_pid, err := os.ReadFile(PidFilePath)
				if err != nil {
					fmt.Println("Failed to read pid file:", err)
					os.Exit(1)
				}
				args = []string{strings.TrimSpace(string(_pid))}
			}
			pid, err := strconv.Atoi(args[0])
			if err != nil {
				cmd.Help()
				os.Exit(1)
			}

			// Check for in-progress operations.
			code, _, err := readSignalProgressFile()
			if err == nil && code != consts.ReloadDone && code != consts.ReloadError &&
				code != consts.UpdateSubDone && code != consts.UpdateSubError &&
				code != consts.UpdateDnsDone && code != consts.UpdateDnsError &&
				code != consts.UpdateRoutingDone && code != consts.UpdateRoutingError {
				fmt.Printf("%v shows another operation is in progress.\n", SignalProgressFilePath)
				return
			}

			// Write discriminator so the SIGHUP handler knows this is a
			// routing update, not a subscription update.
			os.WriteFile(SignalProgressFilePath, []byte{consts.UpdateRoutingSend}, 0644)

			// Send SIGHUP to trigger routing update.
			if err = syscall.Kill(pid, syscall.SIGHUP); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			time.Sleep(500 * time.Millisecond)
			code, _, _ = readSignalProgressFile()
			if code == consts.UpdateRoutingSend {
				fmt.Println("OK")
				return
			}

			for {
				time.Sleep(200 * time.Millisecond)
				code, content, err := readSignalProgressFile()
				if err != nil {
					fmt.Println("OK")
					return
				}
				if code == consts.UpdateRoutingDone || code == consts.UpdateRoutingError {
					fmt.Println(content)
					return
				}
			}
		},
	}
)

func init() {
	updateCmd.AddCommand(updateRoutingCmd)
}
