#!/usr/bin/env python

from petra.lib.models import build_sbom_tree_from_file
from petra.lib.models.sbom_tree import PrintVisitor
#target = '../sbom_data/bom-shelter/in-the-wild/spdx/kustomizer_2.1.0_sbom.spdx.json'
target = 'tests/test_data/test.spdx.json'

root = build_sbom_tree_from_file(target)

root.walk(PrintVisitor(), None)
