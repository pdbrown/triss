PYTHON := python
PYTEST := $(PYTHON) -m pytest
PIP := pip
VERSION := $(shell awk -F\" '/^version/ { print $$2 }' pyproject.toml)
SRC := $(shell find src)
TESTS := $(shell find tests)
DOCKER := docker

assert-venv:
	@test $${VIRTUAL_ENV?Is unset. Must be in a venv.}

dist/triss-$(VERSION).tar.gz: pyproject.toml $(SRC) $(TESTS) | assert-venv
	$(PIP) install '.[qrcode,test]'
	$(PIP) install --upgrade build
	$(MAKE) test
	$(PYTHON) -m build

build: dist/triss-$(VERSION).tar.gz

sign:
	rm -rf dist
	$(MAKE) build
	cd dist && \
	  sha256sum * > SHA256SUMS && \
	  gpg $(GPG_OPTS) --sign --detach-sig --armor SHA256SUMS

docker: sign
	$(DOCKER) build -t triss:$(VERSION) .

dev: | assert-venv
	$(PIP) install --editable '.[qrcode,test]'

test: | assert-venv
	$(PYTEST) -v tests/main tests/generative

stress: | assert-venv
	$(PYTEST) -vs tests/stress

clean:
	git clean -ffdx

.PHONY: assert-venv build sign docker dev test stress clean
