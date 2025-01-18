# GODEBUG

According to [Go, Backwards Compatibility, and GODEBUG][GODEBUG]:

> Any directives in required dependency modules are ignored.

So if you are importing these packages into your own project, or performing your own compilation of this code, you should set the following settings for maximum compatibility:

```go
// go.mod
godebug (
    default=go1.21
    tls10server=1
    tls3des=1
    tlsrsakex=1
)
```

Or…

```bash
GODEBUG=tls10server=1,tls3des=1,tlsrsakex=1
```

(If you don't know how to apply these, read through “[Go, Backwards Compatibility, and GODEBUG][GODEBUG]” to learn how to apply them to your version of Go.)

[GODEBUG]: https://go.dev/doc/godebug

## Up to date?

While we will do our best to keep this document up to date, the latest values we're using live in the `go.mod` file at the root of the repository.
