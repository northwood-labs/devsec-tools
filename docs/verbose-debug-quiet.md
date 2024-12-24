# Verbose/debug/quiet mode

If necessary, you can expose additional information about the requests.

## Verbose

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

## Debug

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

## Quiet

Quiet mode will prevent all logging and error messages from being displayed except for those which are `FATAL`. It will also prevent any _progress_ animations from displaying.
