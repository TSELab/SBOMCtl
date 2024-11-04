# PETRA

In this doc:

[Dir contents]: #contents
[Petra setup]: #setup
[Using Petra]: #petra-usage

## Contents

This directory contains the two modules needed to run the Petra system (currently under submission).

The following files are currently in here
├── bootstrap.sh
├── docs
├── Makefile
├── pyproject.toml
├── requirements.txt
├── src

Of which, `docs` contains documentation, and Makefile, pyproject.toml and
requirements.txt, bootstrap.sh support setting up the project.

## Setup

You can set up a virtual environment in two ways:

```
make init
```

or

```
virtualenv <venv name>
source <venv name>/bin/activate
pip install -r requirements.txt
```

`/src` contains the code needed for this script, and it is split into two modules: petra and cpabe.

### cpabe

cpabe is the python bindings for the rust crate rabe, this is needed to support CP-abe functionality.

Before you run any other code, make sure that these bindings are built by issuing:

```
sudo apt install rustc cargo
cd cpabe

maturin develop
```

This will build the rust code, as well as install an editable version of the
python bindings into the current virtual environment.

### petra

Petra is the main system. If cpabe is installed, you should be able to
install the petra package:

```
cd privateSBOMExchange
pip install -e .
```

### Optional: SBOM datasets

The final setup step pulls SBOM datasets from linked repos:

```
cd SBOMCtl
git submodule update --init
```

## Petra Usage

### Configuration

We provide a simple configuration template for Petra in `config/petra.conf.template`. To provide your own configuration,
point the Petra CLI to your file:

```
from petra.lib.util import config.Config

conf = Config(<path to my config>)
```

**TODO**: Pass config file path as CLI arg.

We also provide the following example configurations:

* `config/bom-only.conf`: a short list of SBOMs to ingest into Petra

### Tests

After the setup, you should be able to run the Petra CLI by running the test files under `/tests`.

For example:

```
python tests/test_models.py
```

Should showcase an encryption and selective decription of target sbom --- make
sure sbom\_data has the sboms you need!
