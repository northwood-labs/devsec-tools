When you compile a Lambda function for local testing, it should be compiled and stored in this directory with the name `bootstrap`.

When the `localdev` is running, this directory is mounted to `/var/runtime` inside the Lamdbda environment.

The contents of this directory (except this `README`) are Git-ignored.
