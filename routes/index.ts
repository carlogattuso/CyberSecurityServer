import { Router } from 'express';

const router: Router = Router();

let controller = require('../controllers/controller');

/**
 * Cyber Security Endpoint
 */

/**
 * RSA Service
 */
router.get('/rsa/pubKey', controller.getPubKey);
router.post('/rsa/sign', controller.sign);
router.post('/rsa/decrypt', controller.decrypt);

/**
 * Non-Repudiation Service
 */
router.post('/nr', controller.getMessage);

/**
 * Homomorphism Service
 */
router.get('/paillier/pubKey', controller.getPallierPubKey);
router.post('/paillier/decrypt', controller.postHomomorphic);

export default router;
