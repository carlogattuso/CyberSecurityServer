'use strict';
import {Request, Response } from 'express';
import * as bc from 'bigint-conversion';
import {KeyPair} from "rsa";
import {sign} from "crypto";
import {toASCII} from "punycode";
import {bufToHex} from "bigint-conversion";
const rsa = require('rsa');

let keyPair: KeyPair;

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
    let message = req.body.message;
    let signature = keyPair.privateKey.sign(bc.hexToBigint(message));
    return res.status(200).send({
        signature: bc.bigintToHex(signature)
    });
};

exports.decrypt = async function (req: Request, res: Response){
    let crypto = req.body.crypto;
    let clearText = keyPair.privateKey.decrypt(bc.hexToBigint(crypto));
    return res.status(200).send({
        clearText: bc.bigintToHex(clearText)
    });
};
