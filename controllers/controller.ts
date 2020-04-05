'use strict';
import {Request, Response } from 'express';
import * as bc from 'bigint-conversion';
import {KeyPair,PublicKey} from "rsa";
import * as http from 'http';
import * as socket from 'socket.io-client';
const rsa = require('rsa');
const sha = require('object-sha');
const crypto = require("crypto");


let keyPair: KeyPair;

let aPubKey;
let TTPubKey;
let key;
let iv;
let message;

let c;
let po;
let pr;
let pkp;

const io = socket.connect('http://localhost:50002', {reconnect: true});

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
    aPubKey = new PublicKey(bc.hexToBigint(json.pubKey.e),bc.hexToBigint(json.pubKey.n));
    let proofDigest = bc.bigintToHex(await aPubKey.verify(bc.hexToBigint(json.signature)));
    let bodyDigest = await digest(body);
    if(bodyDigest.trim() === proofDigest.trim() && checkTimestamp(body.timestamp)) {
        po = json.signature;
        c = body.msg;
        let mBody = JSON.parse(JSON.stringify({type: 2, src: 'B', dst: 'A', timestamp: Date.now()}));

        await digest(mBody)
            .then(data => keyPair.privateKey.sign(bc.hexToBigint(data)))
            .then(data => pr = bc.bigintToHex(data));

        let jsonToSend = JSON.parse(JSON.stringify({
            body: mBody, signature: pr,
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

function checkTimestamp(timestamp:number) {
    const time = Date.now();
    return (timestamp > (time - 300000) && timestamp < (time + 300000));
}

/**
 * Listen the server to download the key when it is available
 */
io.on('get-key', () => {
    let res;
    http
        .get('http://localhost:50001/nrk', resp => {
            resp.on("data", data => {
                res = JSON.parse(data);
            });
            resp.on("end", async () => {
                let body = await JSON.parse(JSON.stringify(res.body));
                TTPubKey = new PublicKey(bc.hexToBigint(res.pubKey.e), bc.hexToBigint(res.pubKey.n));
                let proofDigest = await bc.bigintToHex(TTPubKey.verify(bc.hexToBigint(res.signature)));
                let bodyDigest = await digest(body);
                if(bodyDigest.trim() === proofDigest.trim()) {
                    pkp = res.signature;
                    key = body.msg;
                    iv = body.iv;
                    await decrypt(key, iv);
                    console.log("All data verified");
                    console.log({
                        po: po,
                        pkp: pkp,
                        key: key,
                        message: message
                    });
                }
                else{
                    io.emit('get-key-error', {msg: "Bad authentication of proof of key publication"});
                }
            })
        })
        .on("error", err => {
            console.log("Error: ", err.message);
        });
});

function decrypt(key, iv) {  
   let encryptedText = Buffer.from(c, 'hex');
   let decipher = crypto.createDecipheriv('aes-256-cbc', bc.hexToBuf(key), bc.hexToBuf(iv));
   let decrypted = decipher.update(encryptedText);
   decrypted = Buffer.concat([decrypted, decipher.final()]);
   message = decrypted.toString();
  }

