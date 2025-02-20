import express from 'express';
import { getBook, getBookById } from '../controllers/booksController';


/**
 * @swagger
 * /api/v1/book:
 *  get:
 *      summary: Retrieve all books in DB.
 *      description: Fetches a list of books from the database.
 *      responses:
 *          200:
 *              description: A sucessful response with an array of books.
 *          500:
 *              description: Internal server error.
*/

/** 
 * @swagger
 * /api/v1/book/{id}:
 *  get:
 *      summary: Retrieve a book by ID.
 *      description: Fetches a list of book from the database using its ID.
 *      parameters:
 *          in: path
 *          name: id
 *          description: The unique ID of the book.
 *          schema:
 *              type: string
 *      responses:
 *          200:
 *              description: A sucessful response with the requested book.
 *          404:
 *              description: Book not found.
 *          500:
 *              description: Internal server error.
*/

const router = express.Router();

router.get('/book', getBook);

router.get('/book/:id', getBookById);

export default router;