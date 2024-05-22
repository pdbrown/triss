PYTEST := python -m pytest

test:
	$(PYTEST) -v tests/main tests/generative

stress:
	$(PYTEST) -vs tests/stress


.PHONY: test test-stress
