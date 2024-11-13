import configparser
import copy
import os
import json
import shutil
from lib4sbom.parser import SBOMParser
import configparser
from petra.lib.util.config import Config

from petra.lib.models import *
import cpabe

"This attempts to filter out SBOMs with erroneous formats."

bom_conf = Config("config/bom-only.conf")
sbom_of_interest_dir = [bom_conf.get_sbom_files()[1], bom_conf.get_sbom_files()[2]]
target_sbom_dir = "../sbom_data/bom-shelter/target_sbom"

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
            _ = build_sbom_tree(sbom)
            return None
        except KeyError as e:
            return sbom_file
        except:
            raise Exception
    
    sbom_of_interest = []
    problematic_sboms = []
    for sbom_dir in sbom_of_interest_dir:
        sboms_list = get_json_sboms(sbom_dir)
        sbom_of_interest = sbom_of_interest + sboms_list
    for sbom_file in sbom_of_interest:
        problematic_sbom = build_tree(sbom_file)
        if problematic_sbom is not None:
            problematic_sboms.append(sbom_file)

    # move unproblematic sboms to target directory
    for sbom_file in sbom_of_interest:
        if sbom_file not in problematic_sboms:
            if os.path.exists(os.path.join(target_sbom_dir, sbom_file)):
                pass
            shutil.copy(sbom_file, target_sbom_dir)

    print(len(os.listdir(target_sbom_dir)))


preprocess()

