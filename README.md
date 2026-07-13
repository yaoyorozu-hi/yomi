# yomi (黄泉)

黄泉 is the underworld of Japanese myth — the land the dead descend to, where they
are preserved and, in time, laid to rest. Read another way, 黄泉 (*yomi*) is simply
"reading": to read the record back. The name carries both senses. Claude Code session
data descends to yomi: archived faithfully, made readable again, then the stale are
cleared away.

yomi is a single static Rust binary that owns the session-data plane. It stands on
three pillars:

- **archive** — capture session history into a durable, append-only store. The source
  is never wiped; yomi archives a slice, it does not compact live files.
- **wipe** — retire stale session data by policy. Secrets are handled with care:
  high-sensitivity findings are redacted in the stored copy and the unredacted original
  is quarantined (recoverable), not destroyed.
- **search** — index the archive and read it back — the *yomi* sense of the name.

It also absorbs the legacy `mx codex` store. Codex is frozen read-only: no new writes,
existing archives importable into yomi, and `mx codex read`/`list`/`search` remain
available indefinitely for anything not yet migrated.

The storage root is `~/.yomi/` (override with `YOMI_HOME`).

## Status

**pre-P1.** Design is ratified; implementation has not started. See
[`docs/design.md`](docs/design.md) for the full design — that document is the source of
truth for what yomi is and how it behaves.

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
