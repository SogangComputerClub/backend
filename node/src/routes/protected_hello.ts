import { Router } from 'express';
import { checkAcl } from '../middlewares/auth.js';
import type { User } from '../types/auth.d.ts';
const router = Router();

/**
* @swagger
* /protected/hello:
*  get:
*   summary: Protected hello endpoint
*   description: Returns a greeting message for authenticated users. Requires a valid JWT token.
*   tags: [Protected]
*   security:
*     - bearerAuth: []
*   responses:
*    200:
*     description: A greeting message
*     content:
*      application/json:
*       schema:
*        type: object
*        properties:
*         message:
*          type: string
*          example: "Hello from protected route"
*    401:
*       $ref: '#/components/responses/UnauthorizedError'
*    403:
*       $ref: '#/components/responses/ForbiddenError'
*/
router.get('/hello', checkAcl(), async (_, res) => {
    try {
        res.send({
            message: 'Hello from protected route',
        });
    } catch (error) {
        res.status(500).send({ error: error });
    }
});

// swagger
/**
* @swagger
* /protected/acl_hello:
*  get:
*   summary: Protected hello endpoint, with ACL -
*   description: Returns a greeting message for authenticated users. Requires a valid JWT token.
*   tags: [Protected]
*   security:
*     - bearerAuth: []
*   responses:
*    200:
*     description: A greeting message
*     content:
*      application/json:
*       schema:
*        type: object
*        properties:
*         message:
*           type: string
*           example: "Hello from protected route"
*         user:
*           type: object
*           properties:
*            user_id:
*             type: string
*             example: "34b224dd-a533-49dc-954a-d9bd25394609"
*            email:
*             type: string
*             example: "admin@sgcc.sogang.ac.kr"
*            username:
*             type: string
*             example: "admin"
*    401:
*       $ref: '#/components/responses/UnauthorizedError'
*    403:
*       $ref: '#/components/responses/ForbiddenError'
*/
router.get('/acl_hello', checkAcl({ permission: 'acl_hello', strategy: 'jwt' }), async (req, res) => {
    try {
        const { user_id, email, username } = req.user as User;
        res.send({
            message: 'Hello from protected route',
            user: { user_id, email, username }
        });
    } catch (error) {
        res.status(500).send({ error: error });
    }
});

export default router;
