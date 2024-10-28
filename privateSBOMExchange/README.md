# PETRA

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

Make sure you have a virtual environment set up (e.g., by making make init) or
installing the requirements on a virtual environment using `pip install -r
requirements.txt`.

src contains the code needed for this scrpit, and it is split into two modules: petra and cpabe.

## cpabe

cpabe is the python bindings for the rust crate rabe, this is needed to support CP-abe functionality.
Before you run any other code, make sure that these bindings are built by issuing:

```
maturin develop

```

This will build the rust code, as well as install an editable version of the
python bindings into the current virtual environment.

## petra

Petra is the main system. If cpabe is installed, you should be able to run things by running the test files under `scripts`.

For example:

```
python scrpts/Redactor.py
```

Should showcase an encryption and selective decription of target sbom --- make
sure sbom\_data has the sboms you need!
