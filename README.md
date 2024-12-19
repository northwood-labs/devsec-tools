# DevSecTools

DevSec Tools is a suite of tools that are useful for DevSecOps workflows. Its goal is to simplify and streamline the process of developing, securing, and operating software and systems for the web.

This package provices lower-level Go libraries and a CLI tool for running security scans. It is the CLI equivalent to [devsec.tools](https://devsec.tools).

## Usage

```bash
devsec-tools --help
```

### Check supported HTTP versions for a domain

> [!TIP]
> If you do not provide a _scheme_, `devsec-tools` will assume `https:`. If you explicitly want to test `http:`, you should specify that in the domain name.

```bash
devsec-tools http apple.com
```

```bash
devsec-tools http http://localhost:8080
```

### Check supported TLS versions and cipher suites for a domain

```bash
devsec-tools http google.com
```

## Environment variables

* `DST_CACHE_HOSTS` — When **running as a Lambda function**, this is one or more endpoints (delimited by `;`) that should be used for [Valkey] caching.

    ```bash
    # Example: local dev
    DST_CACHE_HOSTS="localhost:6379"

    # Example: production
    DST_CACHE_HOSTS="server1.host.com:6379;server2.host.com:6379;server3.host.com:6379"
    ```

* `DST_LOG_JSON` — Setting this value to `true` will enable JSON logging without requiring the CLI flag. It will also switch to JSON logging when **running as a Lambda function**.

    ```bash
    DST_LOG_JSON="true"
    ```

* `DST_LOG_VERBOSE` — Setting this value to `1` will enable `INFO`-level logging. Setting this value to `2` will enable `DEBUG`-level logging, and will reveal caller locations. The default log level is `Error`, which allows both `Error` and `Fatal` messages.

    ```bash
    # Equivalent to `devsec-tools -vv`
    DST_LOG_JSON="2"
    ```

* `PORT` — When **running as a local web server**, this will override the port that the local web server runs on (default: `8080`).

    ```bash
    PORT=9000 devsec-tools serve
    ```

## Local web server

For local testing, the CLI exposes a very simple HTTP/1.1 server at <http://localhost:8080>.

```bash
devsec-tools serve
```

### Endpoints

When launching the local web server, it will tell you which HTTP methods and endpoints are available. It exposes both `GET` and `POST`, as appropriate.

### GET

For `GET` endpoints, any parameters are passed as URL-encoded query string parameters. Using the `/http` endpoint as an example:

```http
GET /http?url=https%3A%2F%2Fapple.com HTTP/1.1
Host: localhost:8080
```

### POST

For `POST` endpoints, parameters are passed as a JSON-encoded request body. Using the `/http` endpoint as an example:

```http
POST /http HTTP/1.1
Host: localhost:8080
Content-Type: application/json; charset=utf-8

{"url":"https://apple.com"}
```

## Stdout, stderr

### Without error

The CLI will write _content_ (e.g., a table, JSON output) to `stdout` so that it can be piped to other commands.

#### Output: Table

```bash
devsec-tools http https://apple.com
```

```text
╭──────────────┬───────────╮
│ HTTP Version │ Supported │
├──────────────┼───────────┤
│ 1.1          │ YES       │
│ 2            │ NO        │
│ 3            │ NO        │
╰──────────────┴───────────╯
```

#### Output: JSON

```bash
devsec-tools http https://apple.com --json | jq '.'
```

```json
{
  "hostname": "https://apple.com",
  "http11": true,
  "http2": false,
  "http3": false
}
```

### With error

The CLI will write _errors_ to `stderr`. Use pipe redirection to use errors in `stdout`.

#### Output: Table

```bash
devsec-tools http https://apple.xxx
```

```text
2024-12-15T12:55:43.933112-07:00  ERROR  The hostname `https://apple.xxx` does not support ANY versions of HTTP. It is probable that the hostname is incorrect.
╭──────────────┬───────────╮
│ HTTP Version │ Supported │
├──────────────┼───────────┤
│ 1.1          │ NO        │
│ 2            │ NO        │
│ 3            │ NO        │
╰──────────────┴───────────╯
```

#### Output: JSON

```bash
devsec-tools http https://apple.xxx --json 2>&1 | jq '.'
```

```json
{
  "level": "error",
  "msg": "The hostname `https://apple.xxx` does not support ANY versions of HTTP. It is probable that the hostname is incorrect.",
  "time": "2024-12-15T12:51:42.76971-07:00"
}
{
  "hostname": "https://apple.xxx",
  "http11": false,
  "http2": false,
  "http3": false
}
```

## Verbose/debug/quiet mode

If necessary, you can expose additional information about the requests.

### Verbose

“Single-V” verbose mode will show timestamps for when each test starts. In the following example, you can see that all 3 requests were triggered in the same 1/1000th of a second (`13:01:01.705`). It will also tell you what precisely it is testing.

```bash
devsec-tools http https://apple.com -v
```

```text
2024-12-15T13:01:01.705882-07:00  INFO  Checking domain=https://apple.com http=2
2024-12-15T13:01:01.705903-07:00  INFO  Checking domain=https://apple.com http=1.1
2024-12-15T13:01:01.705886-07:00  INFO  Checking domain=https://apple.com http=3
╭──────────────┬───────────╮
│ HTTP Version │ Supported │
├──────────────┼───────────┤
│ 1.1          │ YES       │
│ 2            │ NO        │
│ 3            │ NO        │
╰──────────────┴───────────╯
```

### Debug

“Double-V” verbose mode will show timestamps for when each test starts, as well as when each test completes. In the following example, you can see that all 3 requests were triggered in the same 1/1000th of a second (`13:01:08.873`).

However, you will see that HTTP/1.1 and HTTP/2 completed the next second (`13:01:09`) while the HTTP/3 test took the full duration of the default 3-second timeout (`13:01:11`).

```bash
devsec-tools http https://apple.com -vv
```

```text
2024-12-15T13:01:08.873470-07:00  INFO  <httptls/httptls.go:152> Checking domain=https://apple.com http=2
2024-12-15T13:01:08.873501-07:00  INFO  <httptls/httptls.go:188> Checking domain=https://apple.com http=3
2024-12-15T13:01:08.873500-07:00  INFO  <httptls/httptls.go:117> Checking domain=https://apple.com http=1.1
2024-12-15T13:01:09.003969-07:00  DEBUG  <httptls/httptls.go:167> Completed domain=https://apple.com http=2
2024-12-15T13:01:09.114025-07:00  DEBUG  <httptls/httptls.go:131> Completed domain=https://apple.com http=1.1
2024-12-15T13:01:11.875427-07:00  DEBUG  <httptls/httptls.go:209> Completed domain=https://apple.com http=3
╭──────────────┬───────────╮
│ HTTP Version │ Supported │
├──────────────┼───────────┤
│ 1.1          │ YES       │
│ 2            │ NO        │
│ 3            │ NO        │
╰──────────────┴───────────╯
```

### Quiet

Quiet mode will prevent all logging and error messages from being displayed except for those which are `FATAL`. It will also prevent any _progress_ animations from displaying.

[Valkey]: https://valkey.io
