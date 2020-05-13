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
 * Secret Sharing Service
 */
router.post('/ss/secret', controller.newSecret);

export default router;
