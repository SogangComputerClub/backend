/** 
 * @swagger
 * /api/v1/book:
 *  get:
 *      summary: Retrieve of all books in DB.
 *      description: Fetches a list of books from the database.
 *      responses:
 *          200:
 *              description: A sucessful response with an array of books.
 *          500:
 *              description: Internal server error.
*/

import express from 'express';
import { getBook, getBookById } from '../controllers/booksController';

const router = express.Router();
router.get('/book', getBook);
router.get('/book/:id', getBookById);

export default router;