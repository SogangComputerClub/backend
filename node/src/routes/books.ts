/*
import express from 'express';
import { getAllBooks } from '../temp';

const router = express.Router();
router.get('/allbooks', getAllBooks);

export default router;
*/

import express from 'express';
import { getAllBooks, getAvailableBooks } from '../controllers/booksController';

const router = express.Router();
router.get('/allbooks', getAllBooks);
router.get('/available', getAvailableBooks);

export default router;