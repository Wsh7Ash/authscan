#!/usr/bin/env python3
import click
from rich.console import Console
console=Console()
@click.group()
def main(): pass
@main.command()
@click.option('--url',required=True)
def check(url):
    console.print(f'[blue]Scanning {url}[/blue]')
    console.print('[green]Done[/green]')
if __name__=='__main__': main()
