#!/usr/bin/env python3

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
import re

import requests
import base58
import axolotl_curve25519 as curve
import sha3
import pyblake2
import mnemonic

VERSION = 4

CHAIN_ID = 'T'
DEFAULT_TESTNET_HOST = "https://testnode1.wavesnodes.com"
DEFAULT_MAINNET_HOST = "https://nodes.wavesnodes.com"
HOST = DEFAULT_TESTNET_HOST

DEFAULT_TX_FEE = 100000
DEFAULT_ASSET_FEE = 100000000
DEFAULT_SPONSOR_FEE = 100000000
DEFAULT_SCRIPT_FEE = 1000000

ERR_EXIT_NO_FUNCTION = 1
ERR_EXIT_NEED_PUBKEY = 10
ERR_EXIT_INVALID_BIP39 = 11
ERR_EXIT_ACCOUNT_NO_MATCH = 12
ERR_EXIT_TIMESTAMP_INVALID = 13
ERR_EXIT_NUMSIGNERS_INVALID = 14
ERR_EXIT_SIGNER_INDEX_NO_MATCH = 15
ERR_EXIT_TX_NO_PROOFS = 16
ERR_EXIT_FILE_NO_EXIST = 17
ERR_EXIT_NOT_ENOUGHT_PROOFS = 18
ERR_EXIT_PROOF_EXISTS = 19

TODO = "todo"

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

def generate_address(pubkey, chain_id):
    # convert input to bytes
    chain_id = str2bytes(chain_id)
    # decode base58 pubkey
    pubkey = base58.b58decode(pubkey)
    # create address
    address_version = bytes([1])
    address = address_version + chain_id + waves_hash(pubkey)[:20]
    checksum = waves_hash(address)[:4]
    # base58 encode pubkey
    address = base58.b58encode(address + checksum)
    return address

def generate_account(seed, chain_id, nonce=0):
    # convert input to bytes
    if isinstance(seed, str):
        seed = str2bytes(seed)
    nonce = nonce.to_bytes(length=4, byteorder='big')
    # generate stuff
    account_seed = waves_hash(nonce + seed)
    privkey = curve.generatePrivateKey(sha256(account_seed))
    pubkey = curve.generatePublicKey(privkey)
    # convert pubkey/privkey to base58
    pubkey = base58.b58encode(pubkey)
    privkey = base58.b58encode(privkey)
    # finally create address
    address = generate_address(pubkey, chain_id)
    return address, pubkey, privkey

def waves_timestamp():
    return int(time.time() * 1000)

def json_dumps(obj):
    return json.dumps(obj, indent=4)

def common_start(sa, sb):
    """ returns the longest common substring from the beginning of sa and sb """
    def _iter():
        for a, b in zip(sa, sb):
            if a == b:
                yield a
            else:
                return

    return ''.join(_iter())

def transfer_asset_non_witness_bytes(pubkey, recipient, assetid, amount, attachment='', feeAsset='', fee=DEFAULT_TX_FEE, timestamp=0):
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
        return sdata

def transfer_asset_payload(address, pubkey, privkey, recipient, assetid, amount, attachment='', feeAsset='', fee=DEFAULT_TX_FEE, timestamp=0):
    sdata = transfer_asset_non_witness_bytes(pubkey, recipient, assetid, amount, attachment, feeAsset, fee, timestamp)

    signature = ""
    if privkey:
        signature = sign(privkey, sdata)
    data = json_dumps({
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
    })

    return data

def issue_asset_non_witness_bytes(pubkey, name, description, quantity, script=None, decimals=2, reissuable=True, fee=DEFAULT_ASSET_FEE, timestamp=0):
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
        return sdata


def issue_asset_payload(address, pubkey, privkey, name, description, quantity, script=None, decimals=2, reissuable=True, fee=DEFAULT_ASSET_FEE, timestamp=0):
    sdata = issue_asset_non_witness_bytes(pubkey, name, description, quantity, script, decimals, reissuable, fee, timestamp)

    signature = ""
    if privkey:
        signature = sign(privkey, sdata)
    data = json_dumps({
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
    })

    return data

def reissue_asset_non_witness_bytes(pubkey, assetid, quantity, reissuable=False, fee=DEFAULT_TX_FEE, timestamp=0):
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
    return sdata

def reissue_asset_payload(address, pubkey, privkey, assetid, quantity, reissuable=False, fee=DEFAULT_TX_FEE, timestamp=0):
    sdata = reissue_asset_non_witness_bytes(pubkey, assetid, quantity, reissuable, fee, timestamp)

    signature = ""
    if privkey:
        signature = sign(privkey, sdata)
    data = json_dumps({
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
    })

    return data

def sponsor_non_witness_bytes(pubkey, assetId, minimalFeeInAssets, fee=DEFAULT_SPONSOR_FEE, timestamp=0):
    if timestamp == 0:
        timestamp = int(time.time() * 1000)
    sdata = b'\x0e' + \
        b'\1' + \
        base58.b58decode(pubkey) + \
        base58.b58decode(assetId) + \
        struct.pack(">Q", minimalFeeInAssets) + \
        struct.pack(">Q", fee) + \
        struct.pack(">Q", timestamp)
    return sdata

def sponsor_payload(address, pubkey, privkey, assetId, minimalFeeInAssets, fee=DEFAULT_SPONSOR_FEE, timestamp=0):
    sdata = sponsor_non_witness_bytes(pubkey, assetId, minimalFeeInAssets, fee, timestamp)

    signature = ""
    if privkey:
        signature = sign(privkey, sdata)

    data = json_dumps({
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
    })

    return data

def set_script_non_witness_bytes(pubkey, script, fee=DEFAULT_SCRIPT_FEE, timestamp=0):
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
    return sdata

def set_script_payload(address, pubkey, privkey, script, fee=DEFAULT_SCRIPT_FEE, timestamp=0):
    sdata = set_script_non_witness_bytes(pubkey, script, fee, timestamp)

    signature = ""
    if privkey:
        signature = sign(privkey, sdata)

    data = json_dumps({
        "type": 13,
        "version": 1,
        "senderPublicKey": pubkey,
        "fee": fee,
        "timestamp": timestamp,
        "script": ('base64:' + script if script else None),
        "proofs": [
            signature
        ]
    })

    return data

def post(host, api, data):
    return requests.post('%s%s' % (host, api), data=data, headers={'content-type': 'application/json'}).json()

def get(host, api):
    return requests.get('%s%s' % (host, api)).json()

def broadcast_tx(data):
    return post(HOST, "/transactions/broadcast", data)

def check_seed(seed):
    m = mnemonic.Mnemonic("english")
    return m.check(seed)

def get_seed_addr_pubkey(args):
    if args.template:
        # check pubkey is provided
        if not args.pubkey:
            print("ERROR: if not signing a pubkey must be provided!")
            sys.exit(ERR_EXIT_NEED_PUBKEY)

        # create address
        seed = None
        privkey = None
        pubkey = args.pubkey
        address = generate_address(pubkey, CHAIN_ID)
    else:
        # get seed from user
        seed = getpass.getpass("Seed: ")

        if args.decodebase58:
            seed = base58.b58decode(seed)
        else:
            # check seed is valid bip39 mnemonic
            if check_seed(seed.strip()):
                seed = seed.strip()
                seed = mnemonic.Mnemonic.normalize_string(seed).split(" ")
                seed = " ".join(seed)
            else:
                a = input("Seed is not a valid bip39 mnemonic are you sure you wish to continue (y/N): ")
                if a not in ("y", "Y"):
                    sys.exit(ERR_EXIT_INVALID_BIP39)

        # create address
        address, pubkey, privkey = generate_account(seed, CHAIN_ID)

        # override pubkey (and hence address)
        if args.pubkey:
            pubkey = args.pubkey
            address = generate_address(pubkey, CHAIN_ID)

        print("Address: " + address)

    # check address from pubkey matches args.account
    if hasattr(args, "account") and address != args.account:
        print("ERROR: Account does not match seed/pubkey!")
        print(f"      Account: {args.account}")
        print("---")
        print(f"      Pubkey:  {pubkey}")
        print(f"      Address: {address}")
        sys.exit(ERR_EXIT_ACCOUNT_NO_MATCH)

    return seed, address, pubkey, privkey

def get_fee(default_fee, address, user_provided_fee):
    fee = default_fee
    if user_provided_fee:
        fee = user_provided_fee
    else:
        try:
            data = get(HOST, f"/addresses/scriptInfo/{address}")
            if "error" in data:
                print(f"Warning: unable to check script fees on address ({address})")
                print(data)
            else:
                fee += data["extraFee"]
        except:
            print(f"WARNING: unable to check script fees on address ({address})")

    return fee

def transfer_run(args, timestamp=0):
    seed, address, pubkey, privkey = get_seed_addr_pubkey(args)

    fee = get_fee(DEFAULT_TX_FEE, address, args.fee)

    data = transfer_asset_payload(address, pubkey, privkey, args.recipient, args.assetid, args.amount, fee=fee, timestamp=timestamp)

    return data

def issue_run(args, timestamp=0):
    seed, address, pubkey, privkey = get_seed_addr_pubkey(args)

    fee = get_fee(DEFAULT_ASSET_FEE, address, args.fee)

    data = issue_asset_payload(address, pubkey, privkey, "ZapToken", "http://zap.me", args.amount, decimals=2, reissuable=True, fee=fee, timestamp=timestamp)

    return data

def reissue_run(args, timestamp=0):
    seed, address, pubkey, privkey = get_seed_addr_pubkey(args)

    fee = get_fee(DEFAULT_ASSET_FEE, address, args.fee)

    data = reissue_asset_payload(address, pubkey, privkey, args.assetid, args.amount, reissuable=True, fee=fee, timestamp=timestamp)
    return data

def sponsor_run(args, timestamp=0):
    seed, address, pubkey, privkey = get_seed_addr_pubkey(args)

    fee = get_fee(DEFAULT_SPONSOR_FEE, address, args.fee)
    
    data = sponsor_payload(address, pubkey, privkey, args.assetid, args.assetfee, fee=fee, timestamp=timestamp)

    return data

def set_script_run(args, timestamp=0):
    seed, address, pubkey, privkey = get_seed_addr_pubkey(args)

    fee = get_fee(DEFAULT_SCRIPT_FEE, address, args.fee)

    # read script data
    with open(args.filename, "r") as f:
        script = f.read().replace("\n", "")

    return set_script_payload(address, pubkey, privkey, script, fee=fee, timestamp=timestamp)

def set_script_remove_run(args, timestamp=0):
    seed, address, pubkey, privkey = get_seed_addr_pubkey(args)

    fee = get_fee(DEFAULT_SCRIPT_FEE, address, args.fee)

    return set_script_payload(address, pubkey, privkey, None, fee=fee, timestamp=timestamp)

def sign_run(args):
    # check that files exist (and are readable)
    for filename in args.filename:
        if not os.path.exists(filename):
            print(f"ERROR: file '{filename}' does not exist!")
            sys.exit(ERR_EXIT_FILE_NO_EXIST)
        with open(filename, "r") as f:
            data = f.read()

    # get seed and account info
    seed, address, pubkey, privkey = get_seed_addr_pubkey(args)

    # process each file
    for filename in args.filename:
        # read tx data 
        with open(filename, "r") as f:
            data = f.read()

        # create sig
        tx = json.loads(data)
        type = tx["type"]
        if type == 4:
            print(":: transfer tx")
            tmp = transfer_asset_payload(None, tx["senderPublicKey"], privkey, tx["recipient"], tx["assetId"], \
                tx["amount"], tx["attachment"], tx["feeAssetId"], tx["fee"], tx["timestamp"])
        elif type == 3:
            print(":: issue tx")
            tmp = issue_asset_payload(None, tx["senderPublicKey"], privkey, tx["name"], tx["description"], \
                tx["quantity"], None, tx["decimals"], tx["reissuable"], tx["fee"], tx["timestamp"])
        elif type == 5:
            print(":: reissue tx")
            tmp = reissue_asset_payload(None, tx["senderPublicKey"], privkey, tx["assetId"], tx["quantity"], \
                tx["reissuable"], tx["fee"], tx["timestamp"])
        elif type == 14:
            print(":: sponsor tx")
            tmp = sponsor_payload(None, tx["senderPublicKey"], privkey, tx["assetId"], \
                tx["minSponsoredAssetFee"], tx["fee"], tx["timestamp"])
        elif type == 13:
            print(":: set script tx")
            tmp = set_script_payload(None, tx["senderPublicKey"], privkey, tx["script"], tx["fee"], \
                tx["timestamp"])
        signature = json.loads(tmp)["proofs"][0]

        # sign result
        print(":: sign result")
        print(tmp)

        # insert sig
        tx["proofs"][args.signerindex] = signature
        data = json_dumps(tx)

        # write
        filename = filename + "_signed%02d" % args.signerindex
        print(f":: save (to '{filename}'")
        with open(filename, "w") as f:
            f.write(data)
        print(data)

def broadcast_run(args):
    if not os.path.exists(args.filename):
        print(f"ERROR: file '{args.filename}' does not exist!")
        sys.exit(ERR_EXIT_FILE_NO_EXIST)
    # read tx data
    with open(args.filename, "r") as f:
        data = f.read()

    response = broadcast_tx(data)
    print(response)

def merge_run(args):
    base_tx = None
    base_filename = None
    for filename in args.filename:
        if not os.path.exists(filename):
            print(f"ERROR: file '{filename}' does not exist!")
            sys.exit(ERR_EXIT_FILE_NO_EXIST)
        # read tx data 
        with open(filename, "r") as f:
            data = f.read()

        if not base_tx:
            base_tx = json.loads(data)
            base_filename = filename
        else:
            # add proof to base tx
            tx = json.loads(data)
            for i in range(len(tx["proofs"])):
                proof = tx["proofs"][i]
                if proof and proof != TODO:
                    if len(base_tx["proofs"]) < i:
                        print("ERROR: not enough proofs")
                        sys.exit(ERR_EXIT_NOT_ENOUGHT_PROOFS)
                    bd_proof = base_tx["proofs"][i]
                    if bd_proof and bd_proof != TODO:
                        print("ERROR: proof already exists")
                        sys.exit(ERR_EXIT_PROOF_EXISTS)
                    base_tx["proofs"][i] = proof
            # update filename
            base_filename = common_start(base_filename, filename)

    # save base_tx
    if not base_filename:
        base_filename = "merged"
    else:
        base_filename += "_merged"
    base_filename += ".json"
    with open(base_filename, "w") as f:
        data = json_dumps(base_tx)
        print(f":: write merged file ({base_filename})")
        print(data)
        f.write(data)

def seed_run(args):
    seed = args.seed
    if args.decodebase58:
        seed = base58.b58decode(seed)
    if not check_seed(seed):
        a = input("Seed is not a valid bip39 mnemonic are you sure you wish to continue (y/N): ")
        if a not in ("y", "Y"):
            sys.exit(ERR_EXIT_INVALID_BIP39)
    address, pubkey, privkey = generate_account(seed, CHAIN_ID)
    print("Address: " + address)
    print("Pubkey: " + pubkey)
    pubkey = base58.b58decode(pubkey)
    print("Pubkey Hex: " + pubkey.hex())

def mnemonic_run(args):
    m = mnemonic.Mnemonic("english")
    seed = m.generate()
    print("Mnemonic: " + seed)
    args.seed = seed
    seed_run(args)

def pubkey_run(args):
    address = generate_address(args.pubkey, CHAIN_ID)
    print("Address: " + address)

def fees_run(args):
    data = get(HOST, f"/addresses/scriptInfo/{args.account}")
    if "error" in data:
        print(data)
    else:
        extra_fee = data["extraFee"]
        print(f"TX:      {DEFAULT_TX_FEE + extra_fee}")
        print(f"ASSET:   {DEFAULT_ASSET_FEE + extra_fee}")
        print(f"SPONSOR: {DEFAULT_SPONSOR_FEE + extra_fee}")
        print(f"SCRIPT:  {DEFAULT_SCRIPT_FEE + extra_fee}")

def construct_parser():
    # construct argument parser
    parser = argparse.ArgumentParser()
    
    parser.add_argument("--version", action="version", version=f"zap_asset {VERSION}")
    parser.add_argument("--host", type=str, help=f"Set node host (default: testnet - '{DEFAULT_TESTNET_HOST}, mainnet - '{DEFAULT_MAINNET_HOST})")
    parser.add_argument("-m", "--mainnet", action="store_true", help="Set to use mainnet (default: false)")
    parser.add_argument("-b", "--broadcast", action="store_true", help="If set broadcast the result (default: false)")
    parser.add_argument("-s", "--save", type=str, help="Save the transaction to file (param is the filename to use)")
    parser.add_argument("-T", "--template", action="store_true", help="No signing, just create a transaction template")
    parser.add_argument("-n", "--numsigners", type=int, default=1, help="The number of signers (default: 1)")
    parser.add_argument("-p", "--pubkey", type=str, help="The pubkey to use (required if a multisig transaction)")
    parser.add_argument("-f", "--fee", type=int, help="The fee to use (if you want to override the default)")
    parser.add_argument("-t", "--timestamp", type=str, help="The timestamp to use (if you want to override the default - ie current time), use a javascript timestamp or '+<X>hours'")
    parser.add_argument("-d", "--decodebase58", action="store_true", help="Decode seeds as base58")
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

    parser_sign_file = subparsers.add_parser("sign_file", help="Add a signature to a transaction file")
    parser_sign_file.add_argument("signerindex", metavar="SIGNERINDEX", type=int, help="The index (0 based) of the signer")
    parser_sign_file.add_argument("filename", metavar="FILENAME", nargs="+", help="The signed transaction filename/s")

    parser_broadcast_file = subparsers.add_parser("broadcast_file", help="Broadcast a signed transaction read from a file")
    parser_broadcast_file.add_argument("filename", metavar="FILENAME", type=str, help="The signed transaction filename")

    parser_merge_file = subparsers.add_parser("merge_file", help="Merge the proofs of a list of transactions")
    parser_merge_file.add_argument("filename", metavar="FILENAME", nargs="+", help="The partially signed transaction filename")

    parser_mnemonic = subparsers.add_parser("mnemonic", help="Create a 12 word mnemonic")

    parser_seed = subparsers.add_parser("seed", help="Convert a seed to an address")
    parser_seed.add_argument("seed", metavar="SEED", type=str, help="The seed")

    parser_pubkey = subparsers.add_parser("pubkey", help="Convert a pubkey to an address")
    parser_pubkey.add_argument("pubkey", metavar="PUBKEY", type=str, help="The pubkey")

    parser_fees = subparsers.add_parser("fees", help="Get the fees of a transactions for an account")
    parser_fees.add_argument("account", metavar="ACCOUNT", type=str, help="The account to request fees for")

    return parser

def run_function(function):
    # set timestamp
    timestamp = waves_timestamp()
    if args.timestamp:
        pattern = r"\+(\d+)hours"
        m = re.search(pattern, args.timestamp)
        if m:
            hours = int(m.group(1))
            timestamp += hours * 60 * 60 * 1000
        else:
            try:
                timestamp = int(args.timestamp)
            except:
                print("ERROR: timestamp not a valid number")
                sys.exit(ERR_EXIT_TIMESTAMP_INVALID)

    # run selected function
    if args.numsigners < 1:
        print("ERROR: numsigners must be an greater then or equal to 1")
        sys.exit(ERR_EXIT_NUMSIGNERS_INVALID)
    if args.template:
        # run without signing
        print(":: template tx (no signing)")
        data = function(args, timestamp=timestamp)

        # fill dummy proofs
        tx = json.loads(data)
        tx["proofs"] = args.numsigners * [TODO]
        data = json_dumps(tx)

        print(data)
    elif args.numsigners == 1:
        # run without multisig
        print(":: sign tx (no multisig)")
        data = function(args, timestamp=timestamp)
        print(data)
    else:
        # run with multisig
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
                    sys.exit(ERR_EXIT_SIGNER_INDEX_NO_MATCH)
                data = function(args, timestamp=timestamp)
                tx = json.loads(data)
                if "proofs" in tx:
                    sigs.append(tx["proofs"][0])
                else:
                    print("ERROR: tx has no 'proofs' field!")
                    sys.exit(ERR_EXIT_TX_NO_PROOFS)
                txs.append(tx)
        print(":: txs")
        print(json_dumps(txs))
        print(":: sigs")
        print(json_dumps(sigs))

        # put the sigs in the final tx
        tx = txs[0]
        tx["proofs"] = sigs
        print(":: final tx")
        print(json_dumps(tx))
        data = json_dumps(tx)

    # save
    if args.save:
        print(f":: save (to '{args.save}')")
        with open(args.save, "w") as f:
            f.write(data)

    # broadcast
    if args.broadcast:
        print(":: broadcast")
        response = broadcast_tx(data)
        print(response)

if __name__ == "__main__":
    parser = construct_parser()
    args = parser.parse_args()

    # set pywaves offline and chain
    CHAIN_ID = 'T'
    HOST = DEFAULT_TESTNET_HOST
    if args.mainnet:
        CHAIN_ID = 'W'
        HOST = DEFAULT_MAINNET_HOST
    if args.host:
        HOST = args.host

    # set appropriate function
    function = None
    if args.command == "transfer":
        function = transfer_run
    elif args.command == "issue":
        function = issue_run
    elif args.command == "reissue":
        function = reissue_run
    elif args.command == "sponsor":
        function = sponsor_run
    elif args.command == "script":
        function = set_script_run
    elif args.command == "script_remove":
        function = set_script_remove_run
    elif args.command == "sign_file":
        sign_run(args)
    elif args.command == "broadcast_file":
        broadcast_run(args)
    elif args.command == "merge_file":
        merge_run(args)
    elif args.command == "mnemonic":
        mnemonic_run(args)
    elif args.command == "seed":
        seed_run(args)
    elif args.command == "pubkey":
        pubkey_run(args)
    elif args.command == "fees":
        fees_run(args)
    else:
        parser.print_help()
        sys.exit(ERR_EXIT_NO_FUNCTION)

    if function:
        run_function(function)
