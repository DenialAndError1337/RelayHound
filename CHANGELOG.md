# Changelog

## Unreleased

### Breaking changes
- Removed the deprecated CLI aliases. Use the
  current spellings:
  - `--find-relay-targets` → **`--find-coercion-targets`**
  - `--scope-file <file>` → **`--exclude @<file>`** (inline rules also accepted,
    e.g. `--exclude 10.0.0.5,@scope.txt`)
  - `--targets-file <file>` → **`--extra-targets @<file>`** (inline targets also
    accepted, e.g. `--extra-targets 10.0.0.5,@targets.txt`)

  These aliases had been hidden (`argparse.SUPPRESS`) and printed a deprecation
  notice for a couple of releases. Commands still using the old spellings will
  now error with `unrecognized arguments`. The internal behavior is unchanged —
  only the flag names were removed.
