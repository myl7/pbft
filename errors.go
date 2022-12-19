// Copyright (C) 2022 myl7
// SPDX-License-Identifier: Apache-2.0

package pbft

import "errors"

var ErrTimestampNotNew = errors.New("request timestamp error: not newer than the latest handled one")
var ErrInvalidSig = errors.New("sig error: invalid signature")
var ErrUnmatchedDigest = errors.New("digest error: the digest of the request is not matched with the digest in the preprepare")
var ErrUnmatchedView = errors.New("view error: the view is not matched with the current node state")
var ErrUnmatchedPP = errors.New("preprepare error: accepted 2 preprepares and the 2 do not match")

var ErrInvalidStorage = errors.New("invalid storage error: value is invalid and not put by the app")
var ErrUnknownNodeID = errors.New("id error: can not use the ID to get the required information of the node")
var ErrNoRequestAfterCommittedLocal = errors.New("request error: no request even after committed-local")
