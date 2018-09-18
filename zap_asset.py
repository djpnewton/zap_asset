#!/bin/python3

import argparse
import getpass
import sys
import pywaves as pw

import pywaves
import pywaves.crypto as crypto
import json
import base64
import base58
import time
import struct

def set_script_create_payload(address, script, txFee=pywaves.DEFAULT_SCRIPT_FEE, timestamp=0):
    rawScript = base64.b64decode(script)
    scriptLength = len(rawScript)
    if timestamp == 0:
        timestamp = int(time.time() * 1000)
    sData = b'\x0d' + \
        b'\1' + \
        crypto.str2bytes(str(pywaves.CHAIN_ID)) + \
        base58.b58decode(address.publicKey) + \
        b'\1' + \
        struct.pack(">H", scriptLength) + \
        crypto.str2bytes(str(rawScript)) + \
        struct.pack(">Q", txFee) + \
        struct.pack(">Q", timestamp)
    signature = crypto.sign(address.privateKey, sData)

    data = json.dumps({
        "type": 13,
        "version": 1,
        "senderPublicKey": address.publicKey,
        "fee": txFee,
        "timestamp": timestamp,
        "script": 'base64:' + script,
        "proofs": [
            signature
        ]
    })

    return data

def get_seed_and_address(args):
    # get seed from user
    seed = getpass.getpass("Seed: ")

    # create address
    address = pw.Address(seed=seed)
    print("Address: " + address.address)

    # check seed matches address
    if address.address != args.account:
        print("Account does not match seed!")
        sys.exit(1)

    return seed, address

def issue_run(args):
    seed, address = get_seed_and_address(args)

    print(address.issueAsset("ZAP!", "", args.amount, decimals=2, reissuable=True)["api-data"])

def reissue_run(args):
    seed, address = get_seed_and_address(args)

    print(address.reissueAsset(pw.Asset(args.assetid), args.amount, reissuable=True)["api-data"])

def sponsor_run(args):
    seed, address = get_seed_and_address(args)

    print(address.sponsorAsset(args.assetid, args.assetfee)["api-data"])

def set_script_run(args):
    seed, address = get_seed_and_address(args)

    # read script data
    with open(args.filename, "r") as f:
        script = f.read()

    print(set_script_create_payload(address, script))

if __name__ == "__main__":
    # parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("-m", "--mainnet", action="store_true", help="Set to use mainnet")
    subparsers = parser.add_subparsers(dest="command")

    parser_issue = subparsers.add_parser("issue", help="Create a zap token with a waves account")
    parser_issue.add_argument("node", metavar="NODE", type=str, help="The node to connect to")
    parser_issue.add_argument("account", metavar="ACCOUNT", type=str, help="The account to create the token with")
    parser_issue.add_argument("amount", metavar="AMOUNT", type=int, help="The amount of tokens to create")

    parser_reissue = subparsers.add_parser("reissue", help="Reissue the zap token")
    parser_reissue.add_argument("node", metavar="NODE", type=str, help="The node to connect to")
    parser_reissue.add_argument("account", metavar="ACCOUNT", type=str, help="The account to create the token with")
    parser_reissue.add_argument("assetid", metavar="ASSETID", type=str, help="The asset id")
    parser_reissue.add_argument("amount", metavar="AMOUNT", type=int, help="The amount of new tokens to create")

    parser_sponsor = subparsers.add_parser("sponsor", help="Sponsor the zap token")
    parser_sponsor.add_argument("node", metavar="NODE", type=str, help="The node to connect to")
    parser_sponsor.add_argument("account", metavar="ACCOUNT", type=str, help="The account to create the token with")
    parser_sponsor.add_argument("assetid", metavar="ASSETID", type=str, help="The asset id")
    parser_sponsor.add_argument("assetfee", metavar="ASSETFEE", type=int, help="The fee in zap to cover the sponsorship")

    parser_script = subparsers.add_parser("script", help="Attach a script to a waves account")
    parser_script.add_argument("node", metavar="NODE", type=str, help="The node to connect to")
    parser_script.add_argument("account", metavar="ACCOUNT", type=str, help="The account to attach the script to")
    parser_script.add_argument("filename", metavar="FILENAME", type=str, help="The script filename (compiled to base64)")

    args = parser.parse_args()

    # set pywaves modes
    pw.setOffline()
    if args.command:
        pw.setNode(args.node, "testnet")
        if args.mainnet:
            pw.setNode(args.node, "mainnet")

    # run appropriate command
    if args.command == "issue":
        issue_run(args)
    elif args.command == "reissue":
        reissue_run(args)
    elif args.command == "sponsor":
        sponsor_run(args)
    elif args.command == "script":
        set_script_run(args)
    else:
        parser.print_help()
