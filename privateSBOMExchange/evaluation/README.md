# Petra Evaluation Guide

This guide provides step-by-step instructions for evaluating **Petra** using SBOM dataset.  
You will download an SBOM corpus, preprocess it, run the evaluation benchmarks, and generate performance plots.

## 1. Download SBOM Dataset

Choose **one** of the following options to obtain the bom-shelter dataset.

### Option 1 – Clone bom-shelter directly
```bash
cd SBOMCTL/sbom-data
git clone https://github.com/chainguard-dev/bom-shelter
```

### Option 2 – Use git submodules
If your repository is already configured with a submodule reference:
```bash
cd SBOMCTL/sbom-data
git submodule init
git submodule update
```
    
### Option 3 – Download from Zenodo
Download the bom-shelter from zenodo into `SBOMCTL/sbom_data` directory:
https://doi.org/10.5281/zenodo.17859760
   


## 2. Setup Petra 

You can set up a virtual environment in two ways:

```bash
make init
```

or

```bash
virtualenv <venv name>
source <venv name>/bin/activate
pip install -r requirements.txt
```

### cpabe

cpabe is the python bindings for the rust crate rabe, this is needed to support CP-abe functionality.

Before you run any other code, make sure that these bindings are built by issuing:

```bash
sudo apt install rustc cargo
cd src/cpabe

maturin develop
```

This will build the rust code, as well as install an editable version of the
python bindings into the current virtual environment.

### petra

Petra is the main system. If cpabe is installed, you should be able to
install the petra package:

```bash
cd privateSBOMExchange
pip install -e .
```

## 2. Preprocess SBOM

Run the preprocessing script to filter and attempt to build SBOM tree for all SBOM files. Successfully built SBOM files will be copied to the target directory specified by `config/config.ini` , while unbuildable files (due to erroneous formats) are skipped.

**Note:** This step may take 20 ~ 30 minutes asit tries to build trees for all SBOMs in the dataset


```bash
cd SBOMCTL/privateSBOMExchange
python evaluation/preprocess_sboms.py
```

## 3. Run Evaluations

Execute the following script to build the SBOM tree, perform CP-ABE operations, and records timing results.

```bash
python evaluation/test_evaluations_AES.py
```
Performance results will be saved automatically in `performance.json` in the results directory configured in `config/config.ini`.

## 4. Plot Performance

Generate performance plots with:

```bash
python evaluation/plot_perf_size_AES.py
```

Output plots will be saved automatically inside the results directory configured in `config/config.ini`.

