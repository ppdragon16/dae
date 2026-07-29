/*
*  SPDX-License-Identifier: AGPL-3.0-only
*  Copyright (c) 2022-2025, daeuniverse Organization <dae@v2raya.org>
*/

package consts

const (
	ReloadSend = '0' + iota
	ReloadProcessing
	ReloadDone
	ReloadError
)

const (
	UpdateSubSend = '4' + iota
	UpdateSubProcessing
	UpdateSubDone
	UpdateSubError
)

const (
	UpdateRoutingSend = '<' + iota
	UpdateRoutingProcessing
	UpdateRoutingDone
	UpdateRoutingError
)
