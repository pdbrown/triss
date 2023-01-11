PYTEST := python -m pytest

test:
	$(PYTEST) -v tests/test_main.py
	# $(PYTEST) -v test_main.py --durations=0

test-stress:
	$(PYTEST) -v tests/test_stress.py -s


.PHONY: test test-stress
