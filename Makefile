test:
	pytest -v test_main.py
	# pytest -v test_main.py --durations=0

test-stress:
	pytest -v test_stress.py -s


.PHONY: test test-stress
