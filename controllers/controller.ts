'use strict';
import {Request, Response } from 'express';
import * as bc from 'bigint-conversion';
import {KeyPair,PublicKey} from "rsa";
const rsa = require('rsa');
const sha = require('object-sha');

let keyPair: KeyPair;

let bPubKey;

let c;
let po;

async function firstAsync() {
    return rsa.generateRandomKeys();
}

firstAsync().then(data => keyPair = data);

exports.getPubKey = async function (req: Request, res: Response){
    return res.status(200).send({
        e: bc.bigintToHex(keyPair.publicKey.e),
        n: bc.bigintToHex(keyPair.publicKey.n)
    });
};

exports.sign = async function (req: Request, res: Response){
    const message = req.body.message;
    let signature = keyPair.privateKey.sign(bc.hexToBigint(message));
    return res.status(200).send({
        signature: bc.bigintToHex(signature)
    });
};

exports.decrypt = async function (req: Request, res: Response){
    const crypto = req.body.crypto;
    let clearText = keyPair.privateKey.decrypt(bc.hexToBigint(crypto));
    return res.status(200).send({
        clearText: bc.bigintToHex(clearText)
    });
};

exports.getMessage = async function (req: Request, res: Response){
    let json = req.body;
    let body = JSON.parse(JSON.stringify(json.body));
    bPubKey = new PublicKey(bc.hexToBigint(json.pubKey.e),bc.hexToBigint(json.pubKey.n));
    let proofDigest = bc.bigintToHex(await bPubKey.verify(bc.hexToBigint(json.signature)));
    let bodyDigest = await sha.digest(body);
    if(bodyDigest === proofDigest) {
        po = json.signature;
        c = body.msg;
        let mBody = JSON.parse(JSON.stringify({type: 2, src: 'B', dst: 'A', timestamp: Date.now()}));
        let sign = '';

        await digest(mBody)
            .then(data => keyPair.privateKey.sign(bc.hexToBigint(data)))
            .then(data => sign = bc.bigintToHex(data));

        let jsonToSend = JSON.parse(JSON.stringify({
            body: mBody, signature: sign,
            pubKey: {e: bc.bigintToHex(keyPair.publicKey.e), n: bc.bigintToHex(keyPair.publicKey.n)}
        }));

        return res.status(200).send(jsonToSend);
    } else {
        res.status(401).send({error:"Bad authentication"});
    }
};

async function digest(obj) {
    return await sha.digest(obj,'SHA-256');
}
