# Tests

```bash
python -m pytest tests/ -v
```

Tests needing `rpmbuild` or `rpmdeps` skip automatically when those tools
are absent, so the suite runs anywhere.

`make_deb()` in `test_debfed.py` builds `.deb` fixtures without `dpkg-deb`,
so no Debian tooling is required to run the suite.
