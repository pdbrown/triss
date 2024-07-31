PYTHON := python
PIP := pip
TESTS := .
DOCKER := docker
PYPI := testpypi

VERSION := $(shell awk -F\" '/^version/ { print $$2 }' pyproject.toml)
SRC := $(shell find src)
TEST_SRC := $(shell find tests)
PYTEST := $(PYTHON) -m pytest
MODULE := '.[qrcode,test]'

assert-venv:
	@test $${VIRTUAL_ENV?Is unset. Must be in a venv.}

dist/triss-$(VERSION).tar.gz: pyproject.toml $(SRC) $(TEST_SRC) | assert-venv
	$(PIP) install $(MODULE)
	$(PIP) install --upgrade build
	$(MAKE) test
	$(PYTHON) -m build

build: dist/triss-$(VERSION).tar.gz

dist/SHA256SUMS.asc: dist/triss-$(VERSION).tar.gz
	cd dist && \
	  sha256sum triss* > SHA256SUMS && \
	  gpg $(GPG_OPTS) --sign --detach-sig --armor SHA256SUMS

sign: dist/SHA256SUMS.asc

publish: dist/SHA256SUMS.asc | assert-venv
	$(PIP) install --upgrade twine
	$(PYTHON) -m twine upload --repository $(PYPI) dist/*.whl dist/*.tar.gz

docker: sign
	$(DOCKER) build -t triss:$(VERSION) .

dev: | assert-venv
	$(PIP) install --editable $(MODULE)

test: | assert-venv
	$(PYTEST) -v -k "$(TESTS)" -W error::UserWarning tests/main tests/generative

stress: | assert-venv
	$(PYTEST) -vs tests/stress

clean:
	git clean -ffdx

.PHONY: assert-venv build sign publish docker dev test stress clean
