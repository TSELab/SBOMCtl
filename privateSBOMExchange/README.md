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

### SBOM datasets

The next setup step pulls SBOM datasets from linked repos:

```
cd SBOMCtl
git submodule update --init
```

### SBOM signing test key generation

The final setup step generates the SBOM signing and verification keys for
Petra. Assuming you have openssl installed, generate DER format ECDSA keys:

```
cd tests
openssl ecparam -name prime256v1 -outform der -genkey -out privkey.der -noout
openssl ec -inform der -in privkey.der -pubout -outform der -out pubkey.der
```

Certain tests will then allow you to pass in the private and public key paths as a command-line argument.

## Petra Usage

### Configuration

**TODO**: Pass config file path as CLI arg.

We provide a simple configuration template for Petra in `config/petra.conf.template`. To provide your own configuration,
point the Petra CLI to your file:

```
from petra.lib.util.config import Config

conf = Config(<path to my config>)
```

Then, you can access the different config fields via:

```
sbom1_file = conf.get_sbom_files()[1]
policy1_file = conf.get_cpabe_policy("<policy name>")
```

We also provide the following example configurations:

* `config/bom-only.conf`: a short list of SBOMs to ingest into Petra
* `config/tiny.conf`: a config for testing Petra with a small SBOM and simple redaction policy
* `config/ip-policy.conf`: a config for testing Petra with a sample IP protection policy
* `config/weaknesses.conf`: a config for testing Petra with a sample vulnerability info protection policy

### Tests

After the setup, you should be able to run the Petra CLI by running the test files under `/tests`.

For example:

```
python tests/test_models.py
```

Should showcase an encryption and selective decription of target sbom --- make
sure sbom\_data has the sboms you need!
