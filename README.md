# goaccessfmt

A best-effort pure-go implementation of parser.c in [goaccess](https://goaccess.io/).

Format docs: <https://goaccess.io/man#custom-log>.

Reference program extracted from goaccess code: [assets/reference.c](assets/reference.c).

Quick test reference.c:

```shell
gcc -fsanitize=address -g -Wall reference.c && ASAN_OPTIONS=detect_leaks=0 ./a.out
```

Obviously this program uses code from goaccess project (MIT).

## Note

### Extension specifiers

goaccessfmt adds an "extension" specifier that does not exist in original goaccess: `%S`. It sets `logitem.Server`.

### Config file format

Currently goaccessfmt `ParseConfigReader()` accepts following options:

- `time-format`, required when `log-format` is not a preset one.
- `date-format`, required when `log-format` is not a preset one.
- `log-format`, a full format string or a preset format.
- `tz`, timezone (do not set this when format is a UNIX timestamp).
- `double-decode`, whether do double decode when parsing request URI.

Other options are silently ignored.
