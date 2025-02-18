/*
import express from 'express';
import { getAllBooks } from '../temp';

const router = express.Router();
router.get('/allbooks', getAllBooks);

export default router;
*/

import express from 'express';
import { getBook, getBookById } from '../controllers/booksController';

const router = express.Router();
router.get('/book', getBook);
router.get('/book/:id', getBookById);

export default router;