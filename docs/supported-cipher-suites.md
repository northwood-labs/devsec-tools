# Supported Cipher Suites

Go only supports a limited number of cipher suites, compared to the hundreds which exist. While this is excellent for security, it also makes it impossible to detect all possible cipher suites using Go's [`crypto/tls`](https://pkg.go.dev/crypto/tls@go1.23.5) package. It _may_ be possible to write a custom library to perform the detections, but that does not exist at the moment.

This library will allow you to look them up, but Go cannot validate them without a custom `crypto/tls` implementation.

* TLS 1.0 and newer are supported.
* SSLv2 and SSLv3 are not supported.

## Supported

### Recommended

* `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256` (`0xC02B`)
* `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384` (`0xC02C`)
* `TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256` (`0xCCA9`)

### Strong

* `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256` (`0xC02F`)
* `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384` (`0xC030`)
* `TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256` (`0xCCA8`)

### Weak (CBC, SHA-1)

* `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA` (`0xC009`)
* `TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA` (`0xC00A`)
* `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA` (`0xC013`)
* `TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA` (`0xC014`)
* `TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256` (`0xC023`)
* `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256` (`0xC027`)

### Insecure (RC4, SHA-1)

[[Source](https://cs.opensource.google/go/go/+/refs/tags/go1.23.5:src/crypto/tls/cipher_suites.go;l=73-95)]

* `TLS_ECDHE_ECDSA_WITH_RC4_128_SHA` (`0xC007`)
* `TLS_ECDHE_RSA_WITH_RC4_128_SHA` (`0xC011`)

## Supported (via `GODEBUG`)

### `tlsrsakex=1`

* `TLS_RSA_WITH_RC4_128_SHA` (`0x0005`)
* `TLS_RSA_WITH_AES_128_CBC_SHA` (`0x002F`)
* `TLS_RSA_WITH_AES_256_CBC_SHA` (`0x0035`)
* `TLS_RSA_WITH_AES_128_CBC_SHA256` (`0x003C`)
* `TLS_RSA_WITH_AES_128_GCM_SHA256` (`0x009C`)
* `TLS_RSA_WITH_AES_256_GCM_SHA384` (`0x009D`)

### `tls3des=1`

* `TLS_RSA_WITH_3DES_EDE_CBC_SHA` (`0x000A`)
* `TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA` (`0xC012`)

## Not supported

Cipher Suites containing:

* `anon` — Insecure
* `ARIA` — Secure; South Korean standard
* `CAMELLIA` — Secure; Japanese standard
* `DES` — Insecure encryption algorithm; obsolete
* `DH` — Insecure key exchange; obsolete
* `DHE` — Insecure key exchange; obsolete
* `DSS` — Insecure encryption algorithm; obsolete
* `ECDH` — Mostly secure key exchange, but not ephemeral. `ECDHE` is implemented instead.
* `EXPORT` — Insecure encryption algorithm; obsolete
* `GOSTR341112` — Weak key exchange, encryption, and hashing; USSR/Russian standard
* `IDEA` — Insecure encryption algorithm; obsolete
* `MD5` — Insecure hashing algorithm; obsolete
* `NULL` — Insecure
* `RC2` — Insecure key exchange and encryption algorithm; obsolete
* `SM3` — Weak key exchange, encryption, and hashing; Chinese standard
* `SM4` — Weak key exchange, encryption, and hashing; Chinese standard
