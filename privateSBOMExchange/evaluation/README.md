# Petra Evaluation Guide

This guide provides step-by-step instructions for evaluating **Petra** using SBOM dataset.   
You will download an SBOM corpus, preprocess it, run the evaluation benchmarks, and generate performance plots.

## **Docker Option (skips Steps 1 and 2 below)**
If you prefer a fully containerized setup (that has all the petra setup and dataset), you can run Petra using the provided Docker file. This option packages Petra + cpabe bindings + the bom-shelter dataset inside the container, so you can start directly from preprocessing and evaluation.

**A. Build the Docker image**
From the repository root (SBOMCtl):
```bash
cd SBOMCtl
docker build -f dockerfiles/petra_evaluation -t petra-eval .
```
**B. Start a long-lived container**
This starts the container in the background and keeps it alive:
```bash
cd SBOMCtl
docker run -d --name petra-eval petra-eval tail -f /dev/null
```
**Enter the container anytime**
```bash
docker exec -it petra-eval bash
```
**C. Run preprocessing, evaluations, and plotting (inside container)**
```bash
cd privateSBOMExchange

python evaluation/preprocess_sboms.py
python evaluation/test_evaluations_AES.py
python evaluation/plot_perf_size_AES.py
```
For details about these scripts see ***steps 3,4,5*** below.

**D. Retrieve results (optional)**

To copy the results directory from the container to your host:
```bash
docker cp petra-eval:/evaluation/privateSBOMExchange/<RESULTS_DIR_ON_CONTAINER> ./petra-results
<RESULTS_DIR_ON_CONTAINER> is the results directory configured in config/config.ini.
```

**E. Stop / remove the container**
```bash
docker stop petra-eval
docker rm petra-eval
```

## 1. Download SBOM Dataset

Choose **one** of the following options to obtain the bom-shelter dataset.

### Option 1 – Clone bom-shelter directly
```bash
cd SBOMCtl/sbom-data
git clone https://github.com/chainguard-dev/bom-shelter
```

### Option 2 – Use git submodules
If your repository is already configured with a submodule reference:
```bash
cd SBOMCtl/sbom-data
git submodule init
git submodule update
```
    
### Option 3 – Download from Zenodo
Download the bom-shelter from zenodo into `SBOMCtl/sbom_data` directory:
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

## 3. Preprocess SBOM

Run the preprocessing script to filter and attempt to build SBOM tree for all SBOM files. Successfully built SBOM files will be copied to the target directory specified by `config/config.ini` , while unbuildable files (due to erroneous formats) are skipped.

**Note:** This step may take 20 ~ 30 minutes as it tries to build trees for all SBOMs in the dataset


```bash
cd SBOMCtl/privateSBOMExchange
python evaluation/preprocess_sboms.py
```

## 4. Run Evaluations

Execute the following script to build the SBOM tree, perform CP-ABE operations, and record timing results.

```bash
python evaluation/test_evaluations_AES.py
```
For each tested policy, Petra saves the performance results in a JSON file named after the policy under the results directory (as configured in config/config.ini).

### A typical output file looks like
```json
{
    "file_size": 844067,
    "build_tree_time": 0.11136531829833984,
    "hash_time": 0.03237414360046387,
    "encrypt_time": 0.004314899444580078,
    "decrypt_time": 0.0029273033142089844,
    "tree_nodes_count": 9155,
    "sbom_tree_storage": 5516808,
    "encrypted_tree_storage": 6176040,
    "decrypted_tree_storage": 9325576,
    "policy": "weaknesses_policy"
}
```
### Field Descriptions
**file_size**: Size of the input SBOM file in bytes.
**build_tree_time**: Time (in seconds) to construct the SBOM tree.
**hash_time**: Time to compute the Merkle-style hashing of all tree nodes.
**encrypt_time**: Time to encrypt all policy-relevant nodes using the CP-ABE scheme.
**decrypt_time**: Time to decrypt the encrypted nodes.
**tree_nodes_count**: Total number of nodes in the constructed SBOM tree.
**sbom_tree_storage**: Size (in bytes) of the plaintext SBOM tree.
**encrypted_tree_storage**: Size (in bytes) of the encrypted SBOM tree.
**decrypted_tree_storage**: Size (in bytes) of the SBOM tree after decryption.
**policy**: Name of the policy used during this run.

### Using the Results for Plotting
The generated performance files are automatically consumed by the plotting scripts in evaluation/, which aggregate metrics across policies and produce comparative performance visualizations.

## 5. Plot Performance

Generate performance plots with:

```bash
python evaluation/plot_perf_size_AES.py
```

For each tested policy, the corresponding plots are automatically saved in a subdirectory named after the policy inside the results directory specified in `config/config.ini`.

### Saved plots

The following plots are generated for each policy:

- build_tree_time_vs_file_size.png    
- decrypt_time_vs_file_size.png          
- decrypt_time_vs_tree_nodes_count.png    
- decrypted_tree_storage_vs_file_size.png 
- encrypt_time_decrypt_time.png           
- encrypt_time_vs_file_size.png          
- encrypt_time_vs_tree_nodes_count.png   
- sbom_tree_storage_vs_file_size.png
- tree_nodes_count_vs_file_size.png
- hash_time_vs_tree_nodes_count.png
- encrypted_tree_storage_vs_file_size.png

### Computed Statistics
The script also calculates the following statistics:

- Average Percentage Increase from SBOM Tree Size to Encrypted Tree Size
- Average Percentage Increase from Encrypted Tree Size to Decrypted Tree Size
- Ratio of encrypted_tree_storage to sbom_tree_storage
- Mean encryption–decryption time difference
- Mean decryption time percentage

## 6. Interpreting the Results and Comparing with the Paper

The performance computed statistics and plots produced by Petra correspond directly to the evaluation presented in the paper.

The plots `encrypt_time_vs_tree_nodes_count.png` and `decrypt_time_vs_tree_nodes_count.png` represent the CP-ABE overhead and correspond to Figures 5 and 6 respectively.

**sbom_tree_storage**, **encrypted_tree_storage**, and **decrypted_tree_storage** metrics illustrate the storage overhead due to building sbom tree, encryption, and decryption respectively.

The **Computed Statistics** :  
**Average Percentage Increase from SBOM Tree Size to Encrypted Tree Size** and **Average Percentage Increase from Encrypted Tree Size to Decrypted Tree Size**  corresponds to encryption and decryption storage overhead results in Section **6.1.1 Storage Overhead** of the paper.

The **Computed Statistics** :  
**Mean decryption time percentage** corresponds to **Decryption Time Percentage** in the **Abstract** and **1. Introduction**


By comparing your generated plots and statistics with those in the paper, you can verify that Petra exhibits the expected performance behavior on your dataset or configuration.