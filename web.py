#!/usr/bin/python3

import json
import base64
from flask import Flask, request, abort, jsonify

import zap_asset

app = Flask(__name__)

@app.route("/")
def index():
    return "ok"

@app.route("/tx_serialize", methods=["POST"])
def tx_serialize():
    content = request.json
    testnet = content["testnet"]
    tx = json.loads(content["tx"])
    print("testnet: {}".format(testnet))
    print("tx: {}".format(tx))

    # set network
    zap_asset.CHAIN_ID = 'T'
    zap_asset.HOST = zap_asset.DEFAULT_TESTNET_HOST
    if not testnet:
        zap_asset.CHAIN_ID = 'W'
        zap_asset.HOST = zap_asset.DEFAULT_MAINNET_HOST

    # serialize
    type = tx["type"]
    if type == 4:
        print(":: transfer tx")
        data = zap_asset.transfer_asset_non_witness_bytes(tx["senderPublicKey"], tx["recipient"], tx["assetId"], \
            tx["amount"], tx["attachment"], tx["feeAssetId"], tx["fee"], tx["timestamp"])
    elif type == 3:
        print(":: issue tx")
        data = zap_asset.issue_asset_non_witness_bytes(tx["senderPublicKey"], tx["name"], tx["description"], \
            tx["quantity"], None, tx["decimals"], tx["reissuable"], tx["fee"], tx["timestamp"])
    elif type == 5:
        print(":: reissue tx")
        data = zap_asset.reissue_asset_non_witness_bytes(tx["senderPublicKey"], tx["assetId"], tx["quantity"], \
            tx["reissuable"], tx["fee"], tx["timestamp"])
    elif type == 14:
        print(":: sponsor tx")
        data = zap_asset.sponsor_non_witness_bytes(tx["senderPublicKey"], tx["assetId"], \
            tx["minSponsoredAssetFee"], tx["fee"], tx["timestamp"])
    elif type == 13:
        print(":: set script tx")
        data = zap_asset.set_script_non_witness_bytes(tx["senderPublicKey"], tx["script"], tx["fee"], \
            tx["timestamp"])
    else:
        return abort("invalid tx type")

    res = {"bytes": base64.b64encode(data).decode("utf-8", "ignore")}
    return jsonify(res)
