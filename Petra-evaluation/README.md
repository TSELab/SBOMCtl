# Petra Evaluation Guide

This README provides instructions to evaluate the Petra project using SBOM data.

## Steps to Evaluate

1. **Clone SBOM Repository**  
   Clone the SBOM repository from `https://github.com/chainguard-dev/bom-shelter` into the `sbom-data` directory:
   ```bash
   cd SBOMCTL/sbom-data
   git clone https://github.com/chainguard-dev/bom-shelter
2. **Preprocess SBOM**
    Run the preprocessing script to filter and attempt to build SBOM files. Successfully built SBOM files will be copied to the target directory, while unbuildable files (due to erroneous formats) are skipped:
    ```bash
    cd SBOMCTL/privateSBOMExchange
    python tests/preprocess_sboms.py
3. **Run Evaluations**
    Execute the following script to build the SBOM tree and perform CPAEBE operations:
    ```bash
    python tests/test_evaluations.py
4. **Plot Performance**
    Generate performance plots with:
    ```bash
    python tests/plot_performance.py
