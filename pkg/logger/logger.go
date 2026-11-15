/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package logger

import (
	"github.com/daeuniverse/dae/pkg/logger/fastlog"
	log "github.com/sirupsen/logrus"
	prefixed "github.com/x-cray/logrus-prefixed-formatter"
	"gopkg.in/natefinch/lumberjack.v2"
)

func SetLogger(logLevel string, disableTimestamp bool, logFileOpt *lumberjack.Logger) {
	level, err := log.ParseLevel(logLevel)
	if err != nil {
		level = log.InfoLevel
	}

	log.SetLevel(level)
	log.SetFormatter(&prefixed.TextFormatter{
		DisableTimestamp: disableTimestamp,
		FullTimestamp:    true,
		TimestampFormat:  "Jan 02 15:04:05",
	})
	// A nil logFileOpt (the reload path) means "keep the current output
	// untouched": it is already validated by the initial run, re-wrapping it
	// here would stack one validator per reload, and re-deriving the log
	// path is both unnecessary and nil-unsafe.
	if logFileOpt != nil {
		// One validator instance shared by both loggers: logrus writes
		// through it, and fastlog's out IS logrus's Out (captured here), so
		// the same gate covers both without the double utf8.Valid a second
		// instance would add.
		out := &fastlog.ByteValidator{W: logFileOpt}
		log.SetOutput(out)
		fastlog.Configure(out)
		logFilePath = logFileOpt.Filename
	}
}

// logFilePath is the file the loggers write to ("" when logging to a stream).
// The janitor's log-tail patrol uses it to watch for foreign writers.
var logFilePath string

// LogFilePath returns the current log file path, or "" when not file-backed.
func LogFilePath() string {
	return logFilePath
}
