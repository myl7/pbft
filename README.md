# myl7/pbft

PBFT (Practical Byzantine Fault Tolerance) implementation focused on composability

The project is aimed for academic use currently.
It may consider production use as a long-term goal, but not now.

## Getting Started

All required interfaces are in the [`traits.go`](traits.go) file.
All you need to do is to implement all (public) interfaces, then pass them to `NewNode` function to initialize a `Node`, and finally pass received PBFT messages from the network to `Node` respective `Handle*` methods.

## Features

- Basic PBFT (request, preprepare, prepare, commit, reply)
- Custom KV storage backend
- Custom network communication
- Custom state machine, to fit whatever you want to do

## Caveats

- No checkpoint
- No view change
- Some ignored (so) edge cases. Search `TODO` comments in the code for details.
- NO READY FOR PRODUCTION USE, yet. Please only use it for academic purposes currently.

## License

Copyright (C) 2022 myl7

SPDX-License-Identifier: Apache-2.0
