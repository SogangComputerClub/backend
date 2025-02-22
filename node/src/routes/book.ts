import express from 'express';
import { getBook, getBookById } from '../controllers/booksController.js';


const router = express.Router();


/**
 * @swagger
 * /book:
 *  get:
 *      summary: Retrieve all books in DB.
 *      description: Fetches a list of books from the database.
 *      responses:
 *          200:
 *              description: A sucessful response with an array of books.
 *          500:
 *              description: Internal server error.
*/
router.get('/book', getBook);

/** 
 * @swagger
 * /book/{id}:
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
router.get('/book/:id', getBookById);

export default router;