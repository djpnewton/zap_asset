#!/bin/python3

import sys
import argparse
import getpass
import json
import base64
import time
import struct
import os
import random
import hashlib

import requests
import base58
import axolotl_curve25519 as curve
import sha3
import pyblake2

CHAIN_ID = 'T'

DEFAULT_TX_FEE = 100000
DEFAULT_ASSET_FEE = 100000000
DEFAULT_SPONSOR_FEE = 100000000
DEFAULT_SCRIPT_FEE = 1000000

def throw_error(msg):
    raise Exception(msg)

def str2bytes(s):
    # warning this method is flawed with some input
    return s.encode("latin-1")

def sign(privkey, message):
    random64 = os.urandom(64)
    return base58.b58encode(curve.calculateSignature(random64, base58.b58decode(privkey), message))

def sha256(data):
    return hashlib.sha256(data).digest()

def waves_hash(data):
    hash1 = pyblake2.blake2b(data, digest_size=32).digest()
    hash2 = sha3.keccak_256(hash1).digest()
    return hash2

def generate_account(seed, chain_id, nonce=0):
    # convert input to bytes
    seed = str2bytes(seed)
    chain_id = str2bytes(chain_id)
    nonce = nonce.to_bytes(length=4, byteorder='big')
    # generate stuff
    account_seed = waves_hash(nonce + seed)
    privkey = curve.generatePrivateKey(sha256(account_seed))
    pubkey = curve.generatePublicKey(privkey)
    address_version = bytes([1])
    address = address_version + chain_id + waves_hash(pubkey)[:20]
    # convert output to base58
    checksum = waves_hash(address)[:4]
    address = base58.b58encode(address + checksum)
    pubkey = base58.b58encode(pubkey)
    privkey = base58.b58encode(privkey)
    return address, pubkey, privkey

def waves_timestamp():
    return int(time.time() * 1000)

def transfer_asset_payload(address, pubkey, privkey, recipient, assetid, amount, attachment='', feeAsset='', fee=DEFAULT_TX_FEE, timestamp=0):
    if amount <= 0:
        msg = 'Amount must be > 0'
        throw_error(msg)
    else:
        if timestamp == 0:
            timestamp = waves_timestamp()
        sdata = b'\4' + \
            b'\2' + \
            base58.b58decode(pubkey) + \
            (b'\1' + base58.b58decode(assetid) if assetid else b'\0') + \
            (b'\1' + base58.b58decode(feeAsset) if feeAsset else b'\0') + \
            struct.pack(">Q", timestamp) + \
            struct.pack(">Q", amount) + \
            struct.pack(">Q", fee) + \
            base58.b58decode(recipient) + \
            struct.pack(">H", len(attachment)) + \
            str2bytes(attachment)
        signature = sign(privkey, sdata)
        data = json.dumps({
            "type": 4,
            "version": 2,
            "senderPublicKey": pubkey,
            "recipient": recipient,
            "assetId": (assetid if assetid else ""),
            "feeAssetId": (feeAsset if feeAsset else ""),
            "amount": amount,
            "fee": fee,
            "timestamp": timestamp,
            "attachment": base58.b58encode(str2bytes(attachment)),
            "proofs": [
                signature
            ]
        }, indent=4)

        return data

def issue_asset_payload(address, pubkey, privkey, name, description, quantity, script=None, decimals=2, reissuable=True, fee=DEFAULT_ASSET_FEE, timestamp=0):
    if len(name) < 4 or len(name) > 16:
        msg = 'Asset name must be between 4 and 16 characters long'
        throw_error(msg)
    else:
        # it looks like script can always be 'None' (might be a bug)
        if script:
            rawScript = base64.b64decode(script)
            scriptLength = len(rawScript)
        if timestamp == 0:
            timestamp = waves_timestamp()
        sdata = b'\3' + \
            b'\2' + \
            str2bytes(str(CHAIN_ID)) + \
            base58.b58decode(pubkey) + \
            struct.pack(">H", len(name)) + \
            str2bytes(name) + \
            struct.pack(">H", len(description)) + \
            str2bytes(description) + \
            struct.pack(">Q", quantity) + \
            struct.pack(">B", decimals) + \
            (b'\1' if reissuable else b'\0') + \
            struct.pack(">Q", fee) + \
            struct.pack(">Q", timestamp) + \
            (b'\1' + struct.pack(">H", scriptLength) + rawScript if script else b'\0')

        signature=sign(privkey, sdata)
        data = json.dumps({
            "type": 3,
            "version": 2,
            "senderPublicKey": pubkey,
            "name": name,
            "description": description,
            "quantity": quantity,
            "decimals": decimals,
            "reissuable": reissuable,
            "fee": fee,
            "timestamp": timestamp,
            "proofs": [
                signature
            ]
        }, indent=4)

        return data

def reissue_asset_payload(address, pubkey, privkey, assetid, quantity, reissuable=False, fee=DEFAULT_TX_FEE, timestamp=0):
    if timestamp == 0:
        timestamp = waves_timestamp()
    sdata = b'\5' + \
        b'\2' + \
        str2bytes(str(CHAIN_ID)) + \
        base58.b58decode(pubkey) + \
        base58.b58decode(assetid) + \
        struct.pack(">Q", quantity) + \
        (b'\1' if reissuable else b'\0') + \
        struct.pack(">Q",fee) + \
        struct.pack(">Q", timestamp)
    signature = sign(privkey, sdata)
    data = json.dumps({
        "type": 5,
        "version": 2,
        "senderPublicKey": pubkey,
        "assetId": assetid,
        "quantity": quantity,
        "timestamp": timestamp,
        "reissuable": reissuable,
        "fee": fee,
        "proofs": [
            signature
        ]
    }, indent=4)

    return data

def sponsor_payload(address, pubkey, privkey, assetId, minimalFeeInAssets, fee=DEFAULT_SPONSOR_FEE, timestamp=0):
    if timestamp == 0:
        timestamp = int(time.time() * 1000)
    sdata = b'\x0e' + \
        b'\1' + \
        base58.b58decode(pubkey) + \
        base58.b58decode(assetId) + \
        struct.pack(">Q", minimalFeeInAssets) + \
        struct.pack(">Q", fee) + \
        struct.pack(">Q", timestamp)
    signature = sign(privkey, sdata)

    data = json.dumps({
        "type": 14,
        "version": 1,
        "senderPublicKey": pubkey,
        "assetId": assetId,
        "fee": fee,
        "timestamp": timestamp,
        "minSponsoredAssetFee": minimalFeeInAssets,
        "proofs": [
            signature
        ]
    }, indent=4)

    return data

def set_script_payload(address, pubkey, privkey, script, fee=DEFAULT_SCRIPT_FEE, timestamp=0):
    if script:
        rawScript = base64.b64decode(script)
        scriptLength = len(rawScript)
    if timestamp == 0:
        timestamp = waves_timestamp()
    sdata = b'\x0d' + \
        b'\1' + \
        str2bytes(str(CHAIN_ID)) + \
        base58.b58decode(pubkey) + \
        (b'\1' + struct.pack(">H", scriptLength) + rawScript if script else b'\0') + \
        struct.pack(">Q", fee) + \
        struct.pack(">Q", timestamp)
    signature = sign(privkey, sdata)

    data = json.dumps({
        "type": 13,
        "version": 1,
        "senderPublicKey": pubkey,
        "fee": fee,
        "timestamp": timestamp,
        "script": ('base64:' + script if script else None),
        "proofs": [
            signature
        ]
    }, indent=4)

    return data

def post(host, api, data):
    return requests.post('%s%s' % (host, api), data=data, headers={'content-type': 'application/json'}).json()

def get_seed_addr_pubkey(args):
    # get seed from user
    seed = getpass.getpass("Seed: ")

    # create address
    address, pubkey, privkey = generate_account(seed, CHAIN_ID)
    print("Address: " + address)

    # check seed matches address
    if args.numsigners == 1 and address != args.account:
        print("Account does not match seed!")
        sys.exit(10)

    # override pubkey
    if args.pubkey:
        pubkey = args.pubkey

    return seed, address, pubkey, privkey

def transfer_run(args, timestamp=0):
    seed, address, pubkey, privkey = get_seed_addr_pubkey(args)

    fee = DEFAULT_TX_FEE
    if args.fee:
        fee = args.fee

    data = transfer_asset_payload(address, pubkey, privkey, args.recipient, args.assetid, args.amount, fee=fee, timestamp=timestamp)

    return data

def issue_run(args, timestamp=0):
    seed, address, pubkey, privkey = get_seed_addr_pubkey(args)

    fee = DEFAULT_ASSET_FEE
    if args.fee:
        fee = args.fee

    data = issue_asset_payload(address, pubkey, privkey, "ZAP!", "", args.amount, decimals=2, reissuable=True, fee=fee, timestamp=timestamp)

    return data

def reissue_run(args, timestamp=0):
    seed, address, pubkey, privkey = get_seed_addr_pubkey(args)

    fee = DEFAULT_ASSET_FEE
    if args.fee:
        fee = args.fee

    data = reissue_asset_payload(address, pubkey, privkey, args.assetid, args.amount, reissuable=True, fee=fee, timestamp=timestamp)
    return data

def sponsor_run(args, timestamp=0):
    seed, address, pubkey, privkey = get_seed_addr_pubkey(args)

    fee = DEFAULT_SPONSOR_FEE
    if args.fee:
        fee = args.fee
    
    data = sponsor_payload(address, pubkey, privkey, args.assetid, args.assetfee, fee=fee, timestamp=timestamp)

    return data

def set_script_run(args, timestamp=0):
    seed, address, pubkey, privkey = get_seed_addr_pubkey(args)

    fee = DEFAULT_SCRIPT_FEE
    if args.fee:
        fee = args.fee

    # read script data
    with open(args.filename, "r") as f:
        script = f.read().replace("\n", "")

    return set_script_payload(address, pubkey, privkey, script, fee=fee, timestamp=timestamp)

def set_script_remove_run(args, timestamp=0):
    seed, address, pubkey, privkey = get_seed_addr_pubkey(args)

    fee = DEFAULT_SCRIPT_FEE
    if args.fee:
        fee = args.fee

    return set_script_payload(address, pubkey, privkey, None, fee=fee, timestamp=timestamp)

def seed_run(args):
    address, pubkey, privkey = generate_account(args.seed, CHAIN_ID)
    print("Address: " + address)
    print("Pubkey: " + pubkey)
    pubkey = base58.b58decode(pubkey)
    print("Pubkey Hex: " + pubkey.hex())

if __name__ == "__main__":
    default_host = "https://testnode1.wavesnodes.com"

    # parse arguments
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", type=str, default=default_host, help=f"Set node host (default: '{default_host})")
    parser.add_argument("-m", "--mainnet", action="store_true", help="Set to use mainnet (default: false)")
    parser.add_argument("-b", "--broadcast", action="store_true", help="If set broadcast the result (default: false)")
    parser.add_argument("-n", "--numsigners", type=int, default=1, help="The number of signers (default: 1)")
    parser.add_argument("-p", "--pubkey", type=str, help="The pubkey to use (required if a multisig transaction)")
    parser.add_argument("-f", "--fee", type=int, default=0, help="The fee to use (if you want to override the default)")
    subparsers = parser.add_subparsers(dest="command")

    parser_transfer = subparsers.add_parser("transfer", help="Transfer an asset")
    parser_transfer.add_argument("account", metavar="ACCOUNT", type=str, help="The account to transfer from the token from")
    parser_transfer.add_argument("recipient", metavar="RECIPIENT", type=str, help="The recipient of the asset")
    parser_transfer.add_argument("assetid", metavar="ASSETID", type=str, help="The asset id")
    parser_transfer.add_argument("amount", metavar="AMOUNT", type=int, help="The amount of tokens to transfer")

    parser_issue = subparsers.add_parser("issue", help="Create a zap token with a waves account")
    parser_issue.add_argument("account", metavar="ACCOUNT", type=str, help="The account to create the token with")
    parser_issue.add_argument("amount", metavar="AMOUNT", type=int, help="The amount of tokens to create")

    parser_reissue = subparsers.add_parser("reissue", help="Reissue the zap token")
    parser_reissue.add_argument("account", metavar="ACCOUNT", type=str, help="The account to create the token with")
    parser_reissue.add_argument("assetid", metavar="ASSETID", type=str, help="The asset id")
    parser_reissue.add_argument("amount", metavar="AMOUNT", type=int, help="The amount of new tokens to create")

    parser_sponsor = subparsers.add_parser("sponsor", help="Sponsor the zap token")
    parser_sponsor.add_argument("account", metavar="ACCOUNT", type=str, help="The account to create the token with")
    parser_sponsor.add_argument("assetid", metavar="ASSETID", type=str, help="The asset id")
    parser_sponsor.add_argument("assetfee", metavar="ASSETFEE", type=int, help="The fee in zap to cover the sponsorship")

    parser_script = subparsers.add_parser("script", help="Attach a script to a waves account")
    parser_script.add_argument("account", metavar="ACCOUNT", type=str, help="The account to attach the script to")
    parser_script.add_argument("filename", metavar="FILENAME", type=str, help="The script filename (compiled to base64)")

    parser_script_remove = subparsers.add_parser("script_remove", help="Remove a script from a waves account")
    parser_script_remove.add_argument("account", metavar="ACCOUNT", type=str, help="The account to remove the `script from")

    parser_seed = subparsers.add_parser("seed", help="Convert a seed to an address")
    parser_seed.add_argument("seed", metavar="SEED", type=str, help="The seed")

    args = parser.parse_args()

    # set pywaves offline and chain
    CHAIN_ID = 'T'
    if args.mainnet:
        CHAIN_ID = 'W'

    # set appropriate function
    command = None
    if args.command == "transfer":
        command = transfer_run
    elif args.command == "issue":
        command = issue_run
    elif args.command == "reissue":
        command = reissue_run
    elif args.command == "sponsor":
        command = sponsor_run
    elif args.command == "script":
        command = set_script_run
    elif args.command == "script_remove":
        command = set_script_remove_run
    elif args.command == "seed":
        seed_run(args)
        sys.exit(0)
    else:
        parser.print_help()
        sys.exit(1)

    # run selected function
    if args.numsigners < 1:
        print("ERROR: numsigners must be an greater then or equal to 1")
        sys.exit(2)
    if args.numsigners == 1:
        # run without multisig
        print(":: sign tx (no multisig)")
        data = command(args)
        print(data)
    else:
        # run with multisig
        timestamp = waves_timestamp()
        sigs = []
        txs = []
        for signerindex in range(args.numsigners):
            print(f":: sign tx (signer index {signerindex})")
            i = input("type the signer index to continue (or just press enter to skip this signer): ")
            if i == "":
                print("skipping..")
                sigs.append("")
            else:
                i = int(i)
                if i != signerindex:
                    print("ERROR: user input does not match signer index!")
                    sys.exit(3)
                data = command(args, timestamp=timestamp)
                tx = json.loads(data)
                if "proofs" in tx:
                    sigs.append(tx["proofs"][0])
                else:
                    print("ERROR: tx has no 'proofs' field!")
                    sys.exit(4)
                txs.append(tx)
        print(":: txs")
        print(txs)
        print(":: sigs")
        print(sigs)

        # put the sigs in the final tx
        tx = txs[0]
        tx["proofs"] = sigs
        print(":: final tx")
        print(tx)
        data = json.dumps(tx)

    # broadcast
    if args.broadcast:
        print(":: broadcast")
        response = post(args.host, "/transactions/broadcast", data)
        print(response)
