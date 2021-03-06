'use strict';
import {Request, Response } from 'express';
import * as bc from 'bigint-conversion';
import {KeyPair,PublicKey} from "rsa";
import * as http from 'http';
import * as socket from 'socket.io-client';

const rsa = require('rsa');
const sha = require('object-sha');
const sss = require('shamirs-secret-sharing');
const crypto = require("crypto");
const paillier = require("paillier-bigint");

const server  = require('socket.io')(50003, {
    path: '',
    serveClient: false,
    // below are engine.IO options
    pingInterval: 10000,
    pingTimeout: 5000,
    cookie: false
});

let keyPair: KeyPair;
let keyPairPaillier;
let aPubKey;
let TTPubKey;
let key;
let iv;
let message;

let c;
let po;
let pr;
let pkp;

let cs : ArrayBuffer[] = [];
let r;

let clientCount = 0;
let sliceCount = 0;

const io = socket.connect('http://localhost:50002', {reconnect: true});

let sockets = [];

async function firstAsync() {
    return rsa.generateRandomKeys(512);
}

firstAsync().then(data => keyPair = data);

server.on('connection', async (socket) => {
    clientCount++;
    console.log("New user connected, total: "+clientCount);
    if(clientCount==5) {
        let secret:Buffer = crypto.randomBytes(64);
        console.log("New secret generated: ");
        console.log({secret: bc.bufToHex(secret)});
        let slices:Array<string> = await sliceSecret(secret);
        console.log("Sliced secret: ");
        console.log({slices:slices});
        Object.keys(server.sockets.sockets).forEach((socket) => {
            server.to(socket).emit('secret',{
                slice:slices.pop(),
                secret:bc.bufToHex(secret)
            });
        });
    }
    socket.emit('hi',"Start sharing keys!");
    socket.on('slice', async (slice) => {
        sliceCount++;
        console.log("New slice has arrived: ");
        console.log({slice: slice});
        console.log("There are "+sliceCount+" slices yet.");
        cs.push(bc.hexToBuf(slice));
        if(sliceCount==3) {
            r = await sss.combine(cs);
            console.log("We can recover now the secret:");
            console.log({secret: bc.bufToHex(r)});
            server.emit('recovered',bc.bufToHex(r));
            sliceCount=0;
        }
    });
    socket.on('disconnect', (socket) => {
        clientCount--;
        console.log("New user disconnected, total: "+clientCount);
    })
});

exports.getPubKey = async function (req: Request, res: Response){
    return res.status(200).send({
        e: bc.bigintToHex(keyPair.publicKey.e),
        n: bc.bigintToHex(keyPair.publicKey.n)
    });
};
/**
 * Get Paillier Key
 */
exports.getPallierPubKey = async function (req: Request, res: Response){
    try {
      keyPairPaillier = await paillier.generateRandomKeys(512);
      res.status(200).send({
        n: bc.bigintToHex(keyPairPaillier["publicKey"]["n"]),
        g: bc.bigintToHex(keyPairPaillier["publicKey"]["g"])
      })
    } catch (err) {
      res.status(500).send({ message: err })
    }
};

exports.postHomomorphic = async function (req: Request, res: Response){
    try {
        console.log('------------------------------------------------');
        const msg = bc.hexToBigint(req.body.totalEncrypted);
        console.log("Sum encrypted votes: " + msg);
        const decrypt =  await keyPairPaillier["privateKey"].decrypt(msg);
        // let zeroFilled = (new Array(decrypt.length()).join('0') + x).substr(-decrypt.length());
        const votes = ("00" + decrypt).slice(-3);
        console.log("Sum votes: " + votes);
        var digits = decrypt.toString().split('');
        console.log("Votes A: " + digits[0]);
        console.log("Votes B: " + digits[1]);
        console.log("Votes C: " + digits[2]);
        console.log('------------------------------------------------');
        res.status(200).send({ msg: bc.bigintToHex(decrypt) })
    } catch (err) {
        res.status(500).send({ message: err })
        }
};

exports.sign = async function (req: Request, res: Response){
    const message = req.body.message;
    console.log("Blind message sent by the client: ", message);
    let signature = keyPair.privateKey.sign(bc.hexToBigint(message));
    console.log("Blind signature message: ", {
        signature: bc.bigintToHex(signature)
    });
    return res.status(200).send({
        signature: bc.bigintToHex(signature)
    });
};

exports.decrypt = async function (req: Request, res: Response){
    const crypto = req.body.crypto;
    console.log("Encrypted message sent by the client: ", crypto);
    let clearText = keyPair.privateKey.decrypt(bc.hexToBigint(crypto));
    console.log("Decrypted message: ", {
        clearText: bc.bigintToHex(clearText)
    });
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

async function sliceSecret (secret:Uint8Array): Promise<Array<string>>{
    console.log('Slicing new secret --> Shares: 5, Threshold: 3');
    let buffers = sss.split(secret, { shares: 5, threshold: 3 });
    let slices: Array<string> = [];
    await buffers.forEach(buffer => slices.push(bc.bufToHex(buffer)));
    return slices;
}

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
