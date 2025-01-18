# DevSec Tools

DevSec Tools is a suite of tools that are useful for DevSecOps workflows. Its goal is to simplify and streamline the process of developing, securing, and operating software and systems for the web.

This package provides both lower-level Go libraries, as well as a CLI tool for running security scans. It is the CLI equivalent to [devsec.tools](https://devsec.tools).

## CLI usage

```bash
devsec-tools --help
```

### Check supported HTTP versions for a domain

> [!TIP]
> If you do not provide a _scheme_, `devsec-tools` will assume `https:`. If you explicitly want to test `http:`, you should specify that in the domain name.

```bash
devsec-tools http --help
devsec-tools http apple.com
```

```bash
devsec-tools http http://localhost:8080
```

### Check supported TLS versions and cipher suites for a domain

```bash
devsec-tools tls --help
devsec-tools tls google.com
```

## Modes

### CLI

When installed locally, `devsec-tools` will run in _CLI-mode_ and operate just like any other CLI tool.

### Lambda

When deployed to an AWS Lambda environment, `devsec-tools` will run in _Lambda-mode_ and will look for events received from endpoints via Amazon API Gateway v2.

### Other?

In the future we may add more modes, depending on support from cloud serverless providers.

We are also planning to investigate the feasibility of [WASM](https://webassembly.org)/[WASI](https://wasi.dev) compatibility, as well as compatibility with [TinyGo](https://tinygo.org).

## Documentation

More thorough documentation can be found in the `./docs/` directory of this repository.
