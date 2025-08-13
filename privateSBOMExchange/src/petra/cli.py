# cli.py
import json
import copy
from pathlib import Path
import click

from lib4sbom.parser import SBOMParser

from petra.lib.models.tree_ops import build_sbom_tree, verify_sameness
from petra.lib.models import MerkleVisitor, EncryptVisitor, DecryptVisitor,SbomNode
from petra.lib.util.config import Config
from petra.lib.models.tree_ops import serialize_tree

#from petra.lib.models import SBOMTree

import cpabe


def _write_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2) + "\n")


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging.")
@click.pass_context
def cli(ctx, verbose):
    """Petra CLI for private SBOM exchange."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose


@cli.command("keygen")
@click.option("--kms-url", help="KMS URL (overrides config).")
@click.option("--aud", help="OIDC audience (overrides config).")
@click.pass_context
def keygen_cmd(ctx, kms_url, aud):
    """
    Fetch/generate a CP-ABE secret key via KMS (or local dev fallback).
    """
    kms_url = kms_url or conf.get_KMS_Server_url()
    aud = aud or conf.get_OIDC_service_audience()

    # TODO: replace with real KMS flow:
    #   key = fetch_key_from_kms(kms_url, aud=aud)
    key = {"mock": True, "kms_url": kms_url, "aud": aud}
    click.echo(json.dumps(key))

@cli.command("encrypt")
@click.option("--input-file","input_file", required=True, help="Path to plaintext SBOM.")
@click.option("--policy","policy_name" ,required=True, help="Policy name.")
@click.option("--config-file","conf_file" ,required=True, type=click.Path(exists=True), help="Path to configuration file.")
@click.option("--output-redacted", required=True, help="Output path for redacted SBOM.")
@click.pass_context
def encrypt_cmd(ctx, input_file, policy_name,conf_file,output_redacted):
    """
    Build tree, encrypt per policy, Merkle-hash, and sign.
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
    """Decrypt an SBOM, enforcing revocation/temporal rules."""
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


@cli.command("verify")
@click.option("--input-redacted", type=click.Path(exists=True), required=True, help="Path to redacted (encrypted) SBOM tree JSON.")
@click.pass_context
def verify_cmd(input_redacted):
    """
    Verify signatures on a redacted tree (no decryption).
    """
    redacted = json.loads(Path(input_redacted).read_text())
    tree = SbomNode.from_dict(redacted)

    if not tree.verify_signature(conf.get_tree_public_key()):
        raise click.ClickException("Signature verification failed.")
    click.echo("Signature verification passed.")


if __name__ == "__main__":  
    cli(obj={})
