import { Router } from 'express';
import { passport } from '../middlewares/auth'

const router = Router();

// swagger
/**
* @swagger
* /api/v1/protected/hello:
*  get:
*   summary: Protected hello endpoint
*   description: Returns a greeting message for authenticated users. Requires a valid JWT token.
*   tags: [Protected]
*   security:
*      - bearerAuth: []
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
*/
router.get('/hello', passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        res.send({
            message: 'Hello from protected route'
        });
    } catch (error) {
        res.status(500).send({ error: error });
    }
});

export default router;
