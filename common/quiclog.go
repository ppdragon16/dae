package common

import (
	"github.com/daeuniverse/quic-go"
	log "github.com/sirupsen/logrus"
)

// quicLogAdapter adapts logrus to quic-go's quic.Logger interface.
// It uses log.StandardLogger(), which is what dae's logger.SetLogger()
// configures (level, formatter, output to /var/log/dae/dae.log).
type quicLogAdapter struct {
	entry    *log.Entry
	logLevel quic.LogLevel
}

// NewQuicLogger creates a quic.Logger backed by logrus' standard logger.
// The initial quic log level is derived from logrus' current level so it stays
// in sync with dae's log_level config. Use quic.SetLogger to inject it.
func NewQuicLogger() quic.Logger {
	quicLevel := quic.LogLevelInfo
	switch log.GetLevel() {
	case log.TraceLevel, log.DebugLevel:
		quicLevel = quic.LogLevelDebug
	case log.ErrorLevel, log.FatalLevel, log.PanicLevel:
		quicLevel = quic.LogLevelError
	}
	return &quicLogAdapter{
		entry:    log.NewEntry(log.StandardLogger()),
		logLevel: quicLevel,
	}
}

func (l *quicLogAdapter) SetLogLevel(level quic.LogLevel) {
	l.logLevel = level
}

func (l *quicLogAdapter) SetLogTimeFormat(format string) {
	// logrus handles timestamp formatting via its own Formatter; no-op.
}

func (l *quicLogAdapter) WithPrefix(prefix string) quic.Logger {
	return &quicLogAdapter{
		entry:    l.entry.WithField("quic", prefix),
		logLevel: l.logLevel,
	}
}

func (l *quicLogAdapter) Debug() bool {
	return l.logLevel >= quic.LogLevelDebug
}

func (l *quicLogAdapter) Errorf(format string, args ...interface{}) {
	if l.logLevel >= quic.LogLevelError {
		l.entry.Errorf("[QUIC] "+format, args...)
	}
}

func (l *quicLogAdapter) Infof(format string, args ...interface{}) {
	if l.logLevel >= quic.LogLevelInfo {
		l.entry.Infof("[QUIC] "+format, args...)
	}
}

func (l *quicLogAdapter) Debugf(format string, args ...interface{}) {
	if l.logLevel >= quic.LogLevelDebug {
		l.entry.Debugf("[QUIC] "+format, args...)
	}
}
