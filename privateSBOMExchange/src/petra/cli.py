import json
import copy
from pathlib import Path
from cryptography.hazmat.primitives import serialization

import click
import requests
from lib4sbom.parser import SBOMParser

from petra.lib.models.tree_ops import build_sbom_tree, verify_sameness
from petra.lib.models import MerkleVisitor, EncryptVisitor, DecryptVisitor,SbomNode
from petra.lib.util.config import Config
from petra.lib.models.tree_ops import serialize_tree, GetTargetNodes, get_membership_proof, verify_membership_proof
import cpabe


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging.")
@click.pass_context
def cli(ctx, verbose):
    """Petra CLI for private SBOM exchange."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


@cli.command("get-decryption-key")
@click.option("--output-file","output_file", help="Path to write the CP-ABE secret key.")
@click.pass_context
def fetch_key_from_kms(ctx,output_file):
    """
    _summary_
    Fetch a CP-ABE decryption (secret) key from the KMS and save it to a file.

    This command:
      1. Retrieves the KMS public key.
      2. Sends an onboarding request to obtain the user's CP-ABE secret key.
      3. Writes the received secret key to ``--output-file``.

    Raises:
        Exception: If the KMS onboarding or public key fetch fails.
    """
    kms_conf = Config("./config/kms.conf")
    kms_service_url = kms_conf.get_kms_service_url()
    response = requests.get("%s/public-key" % kms_service_url)
    if response.status_code != 200:
        print("Failed to get public key")
        exit(1)
    pk = response.json()
    response = requests.post("%s/onboard" % kms_service_url)
    if response.status_code != 200:
        raise Exception(f"Failed to get secret key: {response.text}")
    sk = response.json().get("secret_key")  
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(sk)

@cli.command("encrypt")
@click.option("--input-file","input_file", required=True, help="Path to plaintext SBOM.")
@click.option("--policy","policy_name" ,required=True, help="Policy name.")
@click.option("--config-file","conf_file" ,required=True, type=click.Path(exists=True), help="Path to configuration file.")
@click.option("--output-redacted", required=True, help="Output path for redacted SBOM.")
@click.pass_context
def encrypt_cmd(ctx, input_file, policy_name,conf_file,output_redacted):
    """
    _summary_
    Parse a plaintext SBOM, build its tree, encrypt according to a CP-ABE policy,
    generate a Merkle root hash, sign the tree, and save the redacted/encrypted SBOM.

    This command:
      1. Load Petra configuration from ``conf_file`` (contains CP-ABE keys, policies, signing keys).
      2. Parse the plaintext SBOM from ``input_file``.
      3. Retrieve the CP-ABE policy identified by ``policy_name`` from the configuration.
      4. Build the SBOM tree.
      5. Encrypt the tree’s data fields using CP-ABE according to the policy with the public key.
      6. Compute Merkle hashes for all nodes.
      7. Sign the tree with the configured signing key.
      8. Serialize the resulting encrypted SBOM tree to JSON.
      9. Write the JSON to ``output_redacted``.

    Raises:
        click.ClickException: If the SBOM file does not exist.
    """
    click.echo(f"config path: {conf_file}")
    conf = Config(str(conf_file))

    # SBOM parsing
    sbom_path = Path(input_file)
    if not sbom_path.exists():
        raise click.ClickException(f"SBOM file not found: {sbom_path}")

    parser = SBOMParser()
    parser.parse_file(str(sbom_path))
    sbom = parser.sbom

    # Build tree
    click.echo(f"policy conf:{conf}")
    policy_path = conf.get_cpabe_policy(policy_name)
    click.echo(f"policy object:{policy_path}")
    sbom_tree = build_sbom_tree(sbom, policy_path)

    # Encrypt & hash
    # TODO: put right keys in the path of pk,mk in config files and remove cpabe_setup below
    pk = conf.get_cpabe_public_key()
    mk = conf.get_cpabe_master_key()
    click.echo(f"mk:{mk}")
    pk, mk = cpabe.cpabe_setup()
    #sk = cpabe.cpabe_keygen(pk, mk, conf.get_cpabe_group('ip-group'))
    #with open("../private_key", "w", encoding="utf-8") as f:
    #    f.write(sk)

    click.echo(f"pk:{pk}")

    sbom_tree.accept(EncryptVisitor(pk))
    sbom_tree.accept(MerkleVisitor())
    sbom_tree.sign(conf.get_tree_signing_key())

    #  Write output
    json_tree = json.dumps(serialize_tree(sbom_tree), indent=4)

    with open(output_redacted, "w", encoding="utf-8") as f:
        f.write(json_tree)

    click.echo(f"Encrypted SBOM written to {output_redacted}")


@cli.command("decrypt")
@click.option("--input-file","input_file", required=True, type=click.Path(exists=True),
              help="Path to redacted/encrypted SBOM file")
@click.option("--output-file", "output_file",required=True,
              help="Path to write the decrypted SBOM file")
@click.option("--config", "config_path", required=True, type=click.Path(exists=True),
              help="Path to Petra config.ini")
@click.option("--key-file","key_file", required=True, type=click.Path(exists=True),
              help="Path to CP-ABE secret key file")
def decrypt_cmd(input_file, output_file, config_path, key_file):
    """
    Decrypt an encrypted/redacted SBOM file using a CP-ABE secret key.

    This command:
      1. Loads the encrypted SBOM JSON from --input-file.
      2. Loads the Petra configuration from --config to get the public key for signature checks.
      3. Loads the CP-ABE secret key from --key-file, it assumes the user already obtained it 
      from the key server using get-decryption-key command.
      4. Uses DecryptVisitor with the secret key to recover original node data.
      5. Verifies the decrypted tree's signature for consistency.
      6. Writes the fully decrypted SBOM to --output-file in JSON format.

    Signature verification failures will abort the process.
    """
    conf = Config(str(config_path))

    # Fetch key
    if key_file:
        with open(key_file, "rb") as f:
            sk = f.read()
            
    # Load encrypted SBOM tree
    with open(input_file, "r", encoding="utf-8") as f:
        encrypted_tree_dict = json.load(f)

    # Rebuild tree object
    encrypted_sbom_tree = SbomNode.from_dict(encrypted_tree_dict)


    # Decrypt node data
    with open(key_file, "r", encoding="utf-8") as f:
        sk = f.read()
    decrypt_visitor = DecryptVisitor(sk)
    decrypted_tree = copy.deepcopy(encrypted_sbom_tree)
    decrypted_tree.accept(decrypt_visitor)

    # Verify signature (optional but recommended)
    sig_ok = decrypted_tree.verify_signature(conf.get_tree_public_key())
    click.echo(f"Decrypted tree signature verification passed? {sig_ok}")

    # Verify sameness (optional check)
    # This only works if you still have the original unencrypted tree to compare against
    #passed = verify_sameness(original_tree, decrypted_tree)
    # click.echo(f"Full tree sameness verification passed? {passed}")

    # Save decrypted tree
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(json.dumps(decrypted_tree.to_dict(), indent=4) + "\n")

    click.echo(f"Decrypted SBOM written to {output_file}")


@cli.command("verify-sameness")
@click.option("--decrypted-sbom","decrypted_sbom_file_name", type=click.Path(exists=True), required=True, help="Path to decrypted SBOM tree JSON.")
@click.option("--original-sbom", "orignal_sbom_file_name",type=click.Path(exists=True), required=True, help="Path to original SBOM tree JSON.")
@click.pass_context
def verify_sameness_cmd(ctx,decrypted_sbom_file_name, orignal_sbom_file_name):
    """
    Compare a decrypted SBOM tree with its original unencrypted version to verify sameness.
    This command loads both the decrypted and the original SBOM JSON representations,
    reconstructs them into `SbomNode` tree objects, and runs a full structural and content
    comparison using `verify_sameness`. It returns whether the decrypted version exactly
    matches the original.

    Args:
        decrypted_sbom_file_name (str): Path to the JSON file containing the decrypted SBOM tree.
        orignal_sbom_file_name (str): Path to the JSON file containing the original unencrypted SBOM tree.

    Raises:
        FileNotFoundError: If either file does not exist.
        json.JSONDecodeError: If either file contains invalid JSON.
        ValueError: If SBOM tree reconstruction fails due to malformed input.
    """
    # Load decrypted SBOM tree
    with open(decrypted_sbom_file_name, "r", encoding="utf-8") as f:
        decrypted_tree_dict = json.load(f)

    # Rebuild decrypted tree object
    decrypted_sbom_tree = SbomNode.from_dict(decrypted_tree_dict)
    
    # Load original SBOM tree
    with open(orignal_sbom_file_name, "r", encoding="utf-8") as f:
        orignal_tree_dict = json.load(f)

    # Rebuild original tree object
    orignal_sbom_tree = SbomNode.from_dict(orignal_tree_dict)

    passed = verify_sameness(orignal_sbom_tree, decrypted_sbom_tree)
    click.echo(f"Full tree sameness verification passed? {passed}")


@cli.command("verify-membership")
@click.option("--sbom-file","sbom_file_name", type=click.Path(exists=True), required=True, help="Path to SBOM tree JSON.")
@click.pass_context
def verify_membership_cmd(ctx,sbom_file_name):
    """
    Verify membership proofs for every node in an SBOM tree.

    This loads a JSON-encoded SBOM from `sbom_file_name`, reconstructs the
    `SbomNode` tree, gathers the content hashes for all nodes, and for each
    node computes and verifies a Merkle-style membership proof against the
    SBOM's root hash. The function asserts that every proof verifies.

    Args:
        sbom_file_name (str): Path to the SBOM JSON file to verify.

    Raises:
        AssertionError: If any node's membership proof fails verification.
    """
    # Load SBOM 
    with open(sbom_file_name, "r", encoding="utf-8") as f:
        sbom_dict = json.load(f)

    # Rebuild tree object
    sbom_tree = SbomNode.from_dict(sbom_dict)
   
    # Retrieve hashes of all nodes in the tree
    hash_hunter = GetTargetNodes()
    sbom_tree.accept(hash_hunter)
    target_hashes = hash_hunter.get_hashes()

    #Get and verify membership proof for each node in the tree
    for hash in target_hashes:
        proof = get_membership_proof(sbom_tree, hash)
        assert verify_membership_proof(sbom_tree.hash, hash, proof) == True


if __name__ == "__main__":  
    cli(obj={})
