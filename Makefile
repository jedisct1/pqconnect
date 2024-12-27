USER:=pqconnect
GROUP:=pqconnect

VENV := venv
PYTHON := $(VENV)/bin/python3
PIPFLAGS := $(shell python3 scripts/external.py)

default: build

.PHONY: test clean

venv/bin/activate: pyproject.toml
	python3 -m venv $(VENV)
	$(PYTHON) -m pip install .[dev]

setup: venv/bin/activate

format: venv/bin/activate
	-$(PYTHON) -m isort src
	$(PYTHON) -m black src

lint:  venv/bin/activate
	-$(PYTHON) -m pyflakes src
	-$(PYTHON) -m pylint src
	-$(PYTHON) -m flake8 src
	-$(PYTHON) -m ruff src
	$(PYTHON) -m tryceratops src

type: venv/bin/activate
	-$(PYTHON) -m mypy src
	-$(PYTHON) -m pyright src
	[ -e .pyre_configuration ] || echo "src" | $(VENV)/bin/pyre init
	$(VENV)/bin/pyre check

coverage: venv/bin/activate
	sudo $(PYTHON) -m coverage report -m

dead: venv/bin/activate
	-$(PYTHON) -m vulture src

build-deps:
	scripts/download-build-install-deps

test: venv/bin/activate build-deps
	sudo $(PYTHON) -m coverage run -m unittest discover -v

test_%.py: venv/bin/activate build-deps
	sudo $(PYTHON) -m coverage run -m unittest test/$@

build: build-deps
	python3 -m build
	ls -alh dist/pqconnect*

audit-and-build: venv/bin/activate format lint type dead test build

install-user-and-group:
	-getent passwd ${USER} $2>/dev/null || sudo useradd -g ${GROUP} -r -m -s /bin/false ${USER}
	-getent group ${GROUP} $2>/dev/null || sudo groupadd -r ${GROUP}

install: build install-user-and-group
	-sudo pip install $(PIPFLAGS) dist/pqconnect-0.0.1-py3-none-any.whl

install-systemd-unitfiles:
	sudo cp misc/pqconnect-client.service /etc/systemd/system/
	sudo chmod 644 /etc/systemd/system/pqconnect-client.service
	sudo systemctl daemon-reload

clean:
	rm -rf dist downloads venv .pyre .pyre_configuration .coverage .ruff_cache .mypy_cache

uninstall: clean
	-sudo pip uninstall $(PIPFLAGS) pqconnect

test-run:
	@echo "Start pqconnect in another terminal and press [Enter]:"
	@bash -c read -n1
	curl -L www.pqconnect.net/test.html
