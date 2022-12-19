// Copyright (C) 2022 myl7
// SPDX-License-Identifier: Apache-2.0

package pbft

import "errors"

var ErrInvalidStorage = errors.New("invalid storage error: value is invalid and not put by the app")

var ErrTimestampNotNew = errors.New("request timestamp error: not newer than the latest handled one")
var ErrInvalidSig = errors.New("sig error: invalid signature")
