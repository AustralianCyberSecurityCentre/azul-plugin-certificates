# Azul Plugin Certificates

Inspects PEM encoded certificates and breaks it down into the X.509 components.
## Development Installation

To install azul-plugin-certificates for development run the command
(from the root directory of this project):

```bash
pip install -e .
```

## Usage

Usage on local files:

```bash
$ azul-plugin-certificates malware.file
... example output goes here ...
```

Check `azul-plugin-certificates --help` for advanced usage.

## Python Package management

This python package is managed using a `pyproject.toml` file.

Standardisation of installing and testing the python package is handled through tox.
Tox commands include:

```bash
# Run all standard tox actions
tox
# Run linting only
tox -e style
# Run tests only
tox -e test
```

## Dependency management

Dependencies are managed in the requirements.txt, requirements_test.txt and debian.txt file.

The requirements files are the python package dependencies for normal use and specific ones for tests
(e.g pytest, black, flake8 are test only dependencies).

The debian.txt file manages the debian dependencies that need to be installed on development systems and docker images.

Sometimes the debian.txt file is insufficient and in this case the Dockerfile may need to be modified directly to
install complex dependencies.
