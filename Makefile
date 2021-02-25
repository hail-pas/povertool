checkfiles = povertool api/
black_opts = -l 100 -t py38
py_warn = PYTHONDEVMODE=1

help:
	@echo "povertool development makefile"
	@echo
	@echo  "usage: make <target>"
	@echo  "Targets:"
	@echo  "    up			Updates dev/test dependencies"
	@echo  "    deps		Ensure dev/test dependencies are installed"
	@echo  "    check		Checks that build is sane"
	@echo  "    test		Runs all tests"
	@echo  "    style		Auto-formats the code"

up:
	@poetry update

deps:
	@poetry install --no-root

style: deps
	@poetry run isort -src $(checkfiles)
	@poetry run black $(black_opts) $(checkfiles)

check: deps
	@poetry run black --check $(black_opts) $(checkfiles) || (echo "Please run 'make style' to auto-fix style issues" && false)
	@poetry run flake8 $(checkfiles)
	@poetry run bandit -r $(checkfiles)

test: deps
	@poetry run py.test -s

ci: check test