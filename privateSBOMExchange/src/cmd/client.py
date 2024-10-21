#!/usr/bin/env python
import requests
import click
import os

@click.group()
def cli():
    pass

@cli.command()
@click.argument('cert', type=str)
def enroll(cert):
    """Enrolls a target Petra server (defaults to localhost:5000)"""
    if os.path.exists(cert):
        with open(cert) as fp:
            payload = fp.read()
    else:
        printf(f"Couldn't load {cert}. It doesn't exist!")

    # TODO: we could be cutesy and check it's an actual PEM
    request = {"cert": payload}
    response = requests.post("http://localhost:5000/enroll", json=request)
    print(response.json())


if __name__ == '__main__':
   cli()

