/*
import express from 'express';
import { getAllBooks } from '../temp';

const router = express.Router();
router.get('/allbooks', getAllBooks);

export default router;
*/

import express from 'express';
import { getBooks } from '../controllers/booksController';

const router = express.Router();
router.get('/book', getBooks);

export default router;