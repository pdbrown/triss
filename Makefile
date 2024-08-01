PYTHON := python
PIP := pip
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

assert-venv:
	@test $${VIRTUAL_ENV?Is unset. Must be in a venv.}

dist/$(DIST)-$(VERSION).tar.gz: pyproject.toml $(SRC) $(TEST_SRC) | assert-venv
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

publish: dist/SHA256SUMS.asc | assert-venv
	$(PIP) install --upgrade twine
	$(PYTHON) -m twine upload --repository $(PYPI) dist/*.whl dist/*.tar.gz

upstream: | assert-venv
	$(PIP) install --upgrade $(PKG_UPSTREAM)

docker: dist/SHA256SUMS.asc
	$(DOCKER) build -t $(DIST):$(VERSION) .

dev: | assert-venv
	$(PIP) install --editable $(PKG_LOCAL)

test: | assert-venv
	$(PYTEST) -v -k "$(TESTS)" -W error::UserWarning tests/main tests/generative

stress: | assert-venv
	$(PYTEST) -vs tests/stress

clean:
	git clean -ffdx

.PHONY: assert-venv sign publish docker dev test stress clean
