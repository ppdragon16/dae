/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
 */

package common

import (
	"errors"
	"fmt"
	"strings"
)

// Join joins multiple errors into one.
func Join(errs ...error) error {
	var sb strings.Builder
	var first error
	for _, err := range errs {
		if err != nil {
			if first == nil {
				first = err
			} else {
				sb.WriteString("; ")
				sb.WriteString(err.Error())
			}
		}
	}
	if sb.Len() == 0 {
		return nil
	}
	return fmt.Errorf("%w%s", first, sb.String())
}

// Err creates a simple error with context information.
// This is a lightweight replacement for oops to avoid massive memory allocation
// when proxy nodes go offline.
type Err struct {
	msg     string
	in      string
	wrapped error
	pairs   []any
}

// Error returns the error message.
func (e *Err) Error() string {
	var result string
	if e.in != "" {
		result = e.in + ": "
	}
	if e.msg != "" {
		result += e.msg
	}
	if e.wrapped != nil {
		if result != "" {
			result += ": "
		}
		result += e.wrapped.Error()
	}
	if len(e.pairs) > 0 {
		result += " ("
		for i := 0; i < len(e.pairs); i += 2 {
			if i > 0 {
				result += ", "
			}
			result += fmt.Sprintf("%v=%v", e.pairs[i], e.pairs[i+1])
		}
		result += ")"
	}
	return result
}

// Unwrap returns the wrapped error.
func (e *Err) Unwrap() error {
	return e.wrapped
}

// Is returns true if the target error matches.
func (e *Err) Is(target error) bool {
	if e.wrapped == nil {
		return false
	}
	return errors.Is(e.wrapped, target)
}

// As returns true if the target can be found in the error chain.
func (e *Err) As(target interface{}) bool {
	if e.wrapped == nil {
		return false
	}
	return errors.As(e.wrapped, target)
}

// In adds context about where the error occurred.
func In(context string) *Err {
	return &Err{in: context}
}

// With adds a key-value pair for debugging context.
func (e *Err) With(key string, value any) *Err {
	e.pairs = append(e.pairs, key, value)
	return e
}

// Wrapf wraps an error with a message.
func (e *Err) Wrapf(err error, format string, args ...any) error {
	e.wrapped = err
	e.msg = fmt.Sprintf(format, args...)
	return e
}

// Wrap wraps an error without adding a message.
func (e *Err) Wrap(err error) error {
	e.wrapped = err
	e.msg = err.Error()
	return e
}

// Errf creates a new error with format (without wrapping).
func Errf(format string, args ...any) error {
	return fmt.Errorf(format, args...)
}

// Wrap wraps an error with a simple message.
func Wrap(err error, format string, args ...any) error {
	if err == nil {
		return nil
	}
	if len(args) == 0 {
		return fmt.Errorf("%s: %w", format, err)
	}
	var b strings.Builder
	fmt.Fprintf(&b, format, args...)
	b.WriteString(": ")
	b.WriteString(err.Error())
	return fmt.Errorf(b.String())
}
