# Configuring DataGrip for Valkey

## Overview

[Valkey] is a new-enough fork that there is very little support in existing Redis clients for it. It is a fork of Redis 7.2 (OSS), with additional features added in later releases.

However, where most clients have an issue is in the _hello_ handshake. Where most clients expect `REDIS` in the handshake, Valkey uses `VALKEY`. As a result, most clients fail to connect. However, [DataGrip] allows you to bypass this error, which makes it one of the only working Valkey clients I've been able to find.

## Connecting to the Valkey cache

Using the [Docker Compose] definition from this repository, port `6379` is exposed on `localhost`. There is no authentication required for this local-only development container.

1. After launching DataGrip, create a new _Redis_ connection.

    <div><img src="valkey/01-select-redis.png" alt="Selecting a new Redis data source"></div>

1. The connection requires configuration. As long as there are no changes from the default `compose.yml`, the following screenshots should be correct. Upon choosing _Test Connection_, you will receive a **failure**. This is expected.

    <div><img src="valkey/02-configure-connection.png" alt="Configuring the connection"></div>

    | Field           | Recommended value        |
    |-----------------|--------------------------|
    | Name            | _Whatever name you like_ |
    | Host            | `localhost`              |
    | Port            | `6379`                   |
    | Authentication  | No auth                  |
    | Apply           | ✓                        |
    | Test connection | ✓                        |

1. As previously mentioned, Redis clients tend to fail with Valkey because the client handshake doesn't match what is expected. The workaround is to **disable** the _connection verification_.

    <div><img src="valkey/03-disable-verification.png" alt="Disable the connection verification"></div>

1. Upon a second _Test Connection_, subsequent connections should **succeed**.

    <div><img src="valkey/04-test-again.png" alt="Test the connection again"></div>

1. Once everything looks good, choose the _OK_ button.

    <div><img src="valkey/05-choose-ok.png" alt="Choose OK" width="50%"></div>

1. Ensure that database #0 is selected. If it is not already showing, select the ellipsis (`…`), check _Default database_, then press the _Enter_/_Return_ button.

    <div><img src="valkey/06-select-default-db.png" alt="Enabling the default database #0"></div>

## Viewing cached entries

1. If you want to view the data which has been cached:

    1. Find the string entry you're interested in.
    1. Right-click and choose _Edit Data_. This will show the data on one line.
    1. To expand the view, right-click and choose _Show Record View_.

    <div><br><img src="valkey/07-view-data.png" alt="Viewing the cached data"></div>

1. Without the right-click menus showing, this is what the view looks like with everything opened.

    <div><img src="valkey/08-view-data-clear.png" alt="Viewing the cached data (unobstructed)"></div>

## Deleting cached entries

1. If you have a need to delete a cache value, right-click and choose _Drop_.

    <div><img src="valkey/09-drop.png" alt="Dropping an entry"></div>

1. You will be prompted to confirm the deletion. Choose OK.

    <div><img src="valkey/10-drop-confirm.png" alt="Choose OK" width="50%"></div>

1. The next time the local copy of the API requests this domain name, it will re-cache.

[DataGrip]: https://www.jetbrains.com/datagrip/
[Docker Compose]: https://docs.docker.com/compose/
[Valkey]: https://valkey.io
