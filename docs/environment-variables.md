# Environment variables

> [!IMPORTANT]
> Friendly reminder that environment variables are **always** strings. If you want to parse them as a different data type, your Go code will need to parse them into that type.

* `DST_CACHE_HOSTS` — When **running as a Lambda function**, this is one or more endpoints (delimited by `;`, no spaces) that should be used for [Valkey](https://valkey.io) caching. The default value is `localhost:6379`. If running in a mode that is not _Lambda mode_, this value is ignored.

    ```bash
    # Example: local dev
    DST_CACHE_HOSTS="localhost:6379"

    # Example: production
    DST_CACHE_HOSTS="server1.host.com:6379;server2.host.com:6379;server3.host.com:6379"
    ```

* `DST_CACHE_SECONDS` — When **running as a Lambda function**, this is the (integer) number of seconds that cache entries should persist. The default value is `3600` seconds (1 hour). If running in a mode that is not _Lambda mode_, this value is ignored.

    ```bash
    DST_CACHE_SECONDS="3600"
    ```

* `DST_LOG_JSON` — Setting this value to `true` will enable JSON logging without requiring the CLI flag. The default value is `"false"`.

    ```bash
    DST_LOG_JSON="true"
    ```

* `DST_LOG_VERBOSE` — Setting this value to `1` will enable `INFO`-level logging. Setting this value to `2` will enable `DEBUG`-level logging, and will reveal caller locations. The default value is `ERROR`-level logging, which reports both `ERROR` and `FATAL` messages.

    ```bash
    # Equivalent to `devsec-tools -v`
    DST_LOG_JSON="1"

    # Equivalent to `devsec-tools -vv`
    DST_LOG_JSON="2"
    ```
