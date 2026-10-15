# myl7/pbft

PBFT (practical Byzantine fault tolerance) implementation focused on reusability and composability

## Maintained release

The maintained release is v0.4.0, continuing the v0.2 `Handler` API in
`github.com/myl7/pbft/pkg`. The experimental v0.3 root-package `Node` API is
preserved on the `stale/v0.3` branch and by the unchanged `v0.3.0` tag.
Upgrading from v0.3 requires adapting imports and integration code to the
legacy `/pkg` API; v0.4 is not an extension of that experimental API.

For a module consuming PBFT:

```sh
go get github.com/myl7/pbft/pkg@v0.4.0
```

Historical v0.2.6 remains available at tag `v0.2.6`, `maintenance/0.2`, and
`stale/v0.2/go`. New maintenance belongs on `main`.

## Get Started

A workable example as a test is located in [`test/handler_test.go`](test/handler_test.go)

All you need to do is to create a `Handler` and use it to handle already routed messages

## Features

- Focused on PBFT and decoupled from the rest of the system
  - No network code: Feel free to use TCP/UDP/HTTP...
  - No serialization code: Feel free to use JSON/gob...
  - No crypto code: Feel free to use RSA/Ed25519...
  - No hash code: Feel free to use SHA256/SHA512/SHA3...
- Database as storage
- Zero dependencies

## Caveats

- No view change

## References

- Projects:
  - [corgi-kx/blockchain_consensus_algorithm:pbft](https://github.com/corgi-kx/blockchain_consensus_algorithm/tree/master/pbft)
- Papers:
  - Castro, M., & Liskov, B. (1999, February). [Practical byzantine fault tolerance](http://css.csail.mit.edu/6.824/2014/papers/castro-practicalbft.pdf). In OsDI (Vol. 99, No. 1999, pp. 173-186).
  - Kotla, R., Alvisi, L., Dahlin, M., Clement, A., & Wong, E. (2007, October). [Zyzzyva: speculative byzantine fault tolerance](http://www.cs.cornell.edu/lorenzo/papers/kotla07Zyzzyva.pdf). In Proceedings of twenty-first ACM SIGOPS symposium on Operating systems principles (pp. 45-58).

## License

Copyright (c) 2022 myl7

SPDX-License-Identifier: Apache-2.0

## Go maintenance checks

Tested toolchains are Go 1.27.2 and Go 1.26.9; Go 1.27.2 is recommended for
reproduction. The module's `go 1.18` directive is a minimum language/toolchain
requirement, not a request to install Go 1.18. CI uses the exact toolchains
without automatic switching or a local workspace override.

A C compiler is required for the SQLite test driver, and OpenSSL is required
to generate the existing 4096-bit PKCS#1 test fixtures:

```sh
mkdir -p test/data/rsa
for i in 0 1 2 3 4 5 6; do
  scripts/genrsa.sh "test/data/rsa/${i}_priv.pem" "test/data/rsa/${i}_pub.pem"
done
go build ./...
go vet ./...
go test -race -timeout=60s ./...
```

These checks validate execution and do not establish equal performance across
Go releases or reproduce the paper's full experimental environment.
