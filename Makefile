.PHONY: test lint install rpm clean

test:
	python -m pytest tests/ -v

lint:
	ruff check src/ tests/

install:
	pip install --user -e .

rpm:
	@V=$$(sed -n 's/^__version__ = "\(.*\)"/\1/p' src/debfed/__init__.py); \
	rpmdev-setuptree; \
	git archive --format=tar.gz --prefix="debfed-$$V/" \
	  -o ~/rpmbuild/SOURCES/debfed-$$V.tar.gz HEAD; \
	rpmbuild -bb packaging/debfed.spec

clean:
	rm -rf build dist *.egg-info .pytest_cache .ruff_cache
	find . -name __pycache__ -type d -exec rm -rf {} + 2>/dev/null || true
