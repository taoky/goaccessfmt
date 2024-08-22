# goaccessfmt

A best-effort pure-go implementation of parser.c in [goaccess](https://goaccess.io/).

Reference program extracted from goaccess code: [assets/reference.c](assets/reference.c). 

Quick test reference.c:

```shell
gcc -fsanitize=address -g -Wall reference.c && ASAN_OPTIONS=detect_leaks=0 ./a.out
```

Obviously this program uses code from goaccess project (MIT).
