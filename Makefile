SYSTEM_PYTHON := $(shell command -v python3 || command -v python)
PYTHON := venv/bin/python
PIP := venv/bin/pip
PYTEST := $(PYTHON) -m pytest

TESTS := .
DOCKER := docker
PYPI := pypi

VERSION := $(shell awk -F\" '/^version/ { print $$2 }' pyproject.toml)
SRC := $(shell find src)
TEST_SRC := $(shell find tests)
DIST := triss
PKG_LOCAL := .[test]
PKG_UPSTREAM := $(DIST)[test]


default: dist

venv:
	$(SYSTEM_PYTHON) -m venv venv

dist/$(DIST)-$(VERSION).tar.gz: pyproject.toml $(SRC) $(TEST_SRC) | venv
	$(PIP) install $(PKG_LOCAL)
	$(PIP) install --upgrade build
	$(MAKE) test
	$(PYTHON) -m build

dist: dist/$(DIST)-$(VERSION).tar.gz

dist/SHA256SUMS.asc: dist/$(DIST)-$(VERSION).tar.gz
	cd dist && \
	  sha256sum $(DIST)* > SHA256SUMS && \
	  gpg $(GPG_OPTS) --sign --detach-sig --armor SHA256SUMS

sign: dist/SHA256SUMS.asc

publish: dist/SHA256SUMS.asc | venv
	$(PIP) install --upgrade twine
	$(PYTHON) -m twine upload --repository $(PYPI) dist/*.whl dist/*.tar.gz

upstream: | venv
	$(PIP) install --upgrade $(PKG_UPSTREAM)

docker: dist/SHA256SUMS.asc
	$(DOCKER) build -t $(DIST):$(VERSION) .

dev: | venv
	$(PIP) install --editable $(PKG_LOCAL)

test: | venv
	$(PYTEST) -v -k "$(TESTS)" -W error::UserWarning tests/main tests/generative

stress: | venv
	$(PYTEST) -vs tests/stress

clean:
	git clean -ffdx

.PHONY: default sign publish docker dev test stress clean
