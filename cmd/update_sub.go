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
	updateSubCmd = &cobra.Command{
		Use:   "update-sub [pid]",
		Short: "Re-fetch subscriptions and update dialers without full reload.",
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

			// Read the first line of SignalProgressFilePath.
			code, _, err := readSignalProgressFile()
			if err == nil && code != consts.ReloadDone && code != consts.ReloadError &&
				code != consts.UpdateSubDone && code != consts.UpdateSubError &&
				code != consts.UpdateDnsDone && code != consts.UpdateDnsError &&
				code != consts.UpdateRoutingDone && code != consts.UpdateRoutingError {
				// In progress.
				fmt.Printf("%v shows another operation is in progress.\n", SignalProgressFilePath)
				return
			}

			// Set the progress as UpdateSubSend.
			os.WriteFile(SignalProgressFilePath, []byte{consts.UpdateSubSend}, 0644)

			// Send SIGHUP to trigger subscription update.
			if err = syscall.Kill(pid, syscall.SIGHUP); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			time.Sleep(500 * time.Millisecond)
			code, _, _ = readSignalProgressFile()
			if code == consts.UpdateSubSend {
				// Old version dae is running.
				goto fallback
			}

			for {
				time.Sleep(200 * time.Millisecond)
				code, content, err := readSignalProgressFile()
				if err != nil {
					goto fallback
				}
				if code == consts.UpdateSubDone || code == consts.UpdateSubError {
					fmt.Println(content)
					return
				}
			}
		fallback:
			fmt.Println("OK")
		},
	}
)

func init() {
	rootCmd.AddCommand(updateSubCmd)
}
