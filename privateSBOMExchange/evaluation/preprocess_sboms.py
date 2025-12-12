import configparser
import os
from tqdm import tqdm
import shutil
import time
from lib4sbom.parser import SBOMParser
import configparser
from petra.models.tree_ops import build_sbom_tree

from petra.models import *

"This attempts to filter out SBOMs with erroneous formats."

config = configparser.ConfigParser()
config.read('config/config.ini')
sbom_of_interest_dir = [config['DEFAULT'][key] for key in ('spdx_sbom_path_in-the-wild', 'spdx_sbom_path_in-the-lab')]
target_sbom_dir = config['DEFAULT']['target_sbom_dir']
policy_files = [config['POLICY'][key] for key in ("intellectual_property_policy", "weaknesses_policy")]

os.makedirs(target_sbom_dir, exist_ok=True)

def get_json_sboms(sbom_dir):
    "Interested only in JSON SBOMs. This gets only json SBOM file from bom-shelter"
    json_sboms = []
    for sbom in os.listdir(sbom_dir):
        sbom_file = os.path.join(sbom_dir, sbom)
        if sbom_file.endswith('.json'):
            json_sboms.append(sbom_file)
    return json_sboms

def preprocess():
    def build_tree(sbom_file):
        SBOM_parser = SBOMParser()   
        SBOM_parser.parse_file(sbom_file)   
        sbom=SBOM_parser.sbom
        try:
            time_tree="(\"epoch:1767744000\")"
            _ = build_sbom_tree(sbom,time_tree, policy_files[0])
            return None
        except KeyError as e:
            return sbom_file
        except:
            raise Exception
    start = time.time()
    sbom_of_interest = []
    problematic_sboms = []
    for sbom_dir in sbom_of_interest_dir:
        sboms_list = get_json_sboms(sbom_dir)
        sbom_of_interest = sbom_of_interest + sboms_list
    for sbom_file in tqdm(sbom_of_interest,desc="Preprocessing SBOMs"):
        problematic_sbom = build_tree(sbom_file)
        if problematic_sbom is not None:
            problematic_sboms.append(sbom_file)

    # move unproblematic sboms to target directory
    for sbom_file in sbom_of_interest:
        if sbom_file not in problematic_sboms:
            if os.path.exists(os.path.join(target_sbom_dir, sbom_file)):
                pass
            shutil.copy(sbom_file, target_sbom_dir)
    end = time.time()
    elapsed_minutes = (end - start) / 60
    print(f"Elapsed time: {elapsed_minutes:.2f} minutes")

    print(len(os.listdir(target_sbom_dir)))


preprocess()

