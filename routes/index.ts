import { Router } from 'express';

const router: Router = Router();

let controller = require('./../controllers/controller');

/**
 * Cyber Security Endpoint
 */

router.get('/pubKey', controller.getPubKey);
router.post('/sign', controller.sign);
router.post('/decrypt', controller.decrypt);

export default router;
