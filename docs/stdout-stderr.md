# Stdout, stderr

## Without error

The CLI will write _content_ (e.g., a table, JSON output) to `stdout` so that it can be piped to other commands.

## Output: Table

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

## Output: JSON

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

## With error

The CLI will write _errors_ to `stderr`. Use pipe redirection to use errors in `stdout`.

## Output: Table

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

## Output: JSON

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
