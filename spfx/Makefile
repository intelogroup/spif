.PHONY: test bench

test:
	pytest tests/ -q --ignore=tests/test_fuzz.py --ignore=tests/test_mcp_tools.py --ignore=tests/test_gemini_adapter.py

# Runs every benchmark script that has a __main__, redirecting each script's
# stdout/stderr into results/<name>.txt. Slower/noisier than `make test` —
# not part of CI, run manually or on a nightly job.
bench:
	mkdir -p results
	for f in benchmarks/*.py; do \
		name=$$(basename $$f .py); \
		if [ "$$name" = "__init__" ]; then continue; fi; \
		echo "Running $$name..."; \
		python $$f > results/$$name.txt 2>&1 || echo "  ($$name exited non-zero, see results/$$name.txt)"; \
	done
