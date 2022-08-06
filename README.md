# myl7/pbft

PBFT (practical Byzantine fault tolerance) implementation focused on reusability and composability

## Get Started

A workable example as a test is located in [`test/handler_test.go`](test/handler_test.go)

All you need to do is to create a `Handler` and use it to handle already routed messages

## Features

- Focused on PBFT and decoupled from the rest of the system
  - No network code: Feel free to use TCP/UDP/HTTP...
  - No serialization code: Feel free to use JSON/gob...
  - No crypto code: Feel free to use RSA/Ed25519...
  - No hash code: Feel free to use SHA256/SHA512/SHA3...
- Fine-grained locks other than only one mutex for the whole node

## Caveats

- No view change
- No checkpoint: h-H sequence number range limit and log garbage collection

## References

- Projects:
  - [corgi-kx/blockchain_consensus_algorithm:pbft](https://github.com/corgi-kx/blockchain_consensus_algorithm/tree/master/pbft)
- Papers:
  - Castro, M., & Liskov, B. (1999, February). [Practical byzantine fault tolerance](http://css.csail.mit.edu/6.824/2014/papers/castro-practicalbft.pdf). In OsDI (Vol. 99, No. 1999, pp. 173-186).
  - Kotla, R., Alvisi, L., Dahlin, M., Clement, A., & Wong, E. (2007, October). [Zyzzyva: speculative byzantine fault tolerance](http://www.cs.cornell.edu/lorenzo/papers/kotla07Zyzzyva.pdf). In Proceedings of twenty-first ACM SIGOPS symposium on Operating systems principles (pp. 45-58).

## License

Copyright (c) 2022 myl7

SPDX-License-Identifier: Apache-2.0
