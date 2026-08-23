// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>

package internal

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
)

// MissingConstantsError is returned by [RewriteConstants].
//
// It replicates the removed (*ebpf.CollectionSpec).RewriteConstants error
// type from cilium/ebpf < v0.22.
type MissingConstantsError struct {
	// The constants missing from .rodata.
	Constants []string
}

func (m *MissingConstantsError) Error() string {
	return fmt.Sprintf("some constants are missing from .rodata: %s", strings.Join(m.Constants, ", "))
}

// RewriteConstants replaces the value of multiple constants in a
// CollectionSpec. It reimplements the removed
// (*ebpf.CollectionSpec).RewriteConstants API from cilium/ebpf < v0.22,
// which is now spelled via CollectionSpec.Variables.
func RewriteConstants(spec *ebpf.CollectionSpec, constants map[string]interface{}) error {
	var missing []string
	for name, value := range constants {
		v, ok := spec.Variables[name]
		if !ok {
			missing = append(missing, name)
			continue
		}
		if !v.Constant() {
			return fmt.Errorf("variable %s is not a constant", name)
		}
		if err := v.Set(value); err != nil {
			return fmt.Errorf("rewriting constant %s: %w", name, err)
		}
	}
	if len(missing) != 0 {
		return fmt.Errorf("rewrite constants: %w", &MissingConstantsError{Constants: missing})
	}
	return nil
}
