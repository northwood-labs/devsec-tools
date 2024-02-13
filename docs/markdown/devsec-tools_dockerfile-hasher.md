## devsec-tools dockerfile-hasher

Rewrites a Dockerfile with SHA256 digests of the images.

### Synopsis

Since Docker tags can be re-pointed to different images, it is often useful
to rewrite the Dockerfile with the SHA256 digest of the image.

This command reads the contents of the Dockerfile from disk and parses it
into an Abstract Syntax Tree (AST). It then rewrites the lines in the
Dockerfile with the SHA256 digest of the image.

This is described (briefly) in the Center for Internet Security (CIS) Docker
Benchmark, in section §6.1.

```
devsec-tools dockerfile-hasher [flags]
```

### Options

```
  -f, --dockerfile string   Path to the Dockerfile to parse/rewrite. (default "Dockerfile")
  -h, --help                help for dockerfile-hasher
  -w, --write               Write the changes back to the Dockerfile.
```

### Options inherited from parent commands

```
  -q, --quiet     Disable all logging output.
  -v, --verbose   Enable verbose output.
```

### SEE ALSO

* [devsec-tools](devsec-tools.md)  - A set of useful tools for DevSecOps workflows.
