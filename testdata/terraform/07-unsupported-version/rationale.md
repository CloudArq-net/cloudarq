# 07 — an unsupported major version is refused

**Hand-written**: a plan-shaped document with `format_version: "2.0"`.

The format: "We will increment the major version, e.g. "2.0", for changes that are not
backward-compatible. Reject any input which reports an unsupported major version." Both
readers refuse it with a sentence naming the version and the major version they understand.
Nothing is read from it: a format this reader does not understand, read anyway, could report
a role as absent.

Source: https://developer.hashicorp.com/terraform/internals/json-format (format_version).
