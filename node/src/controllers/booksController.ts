import 'dotenv/config';
import { Request, Response } from 'express';
import { pool } from '../middlewares/db';

// Get All Books
export const getAllBooks = async (req: Request, res: Response) => {
    try {
        const result = await pool.query('SELECT * FROM books');
        res.json(result.rows);
    } catch(error){
        console.error('Error fetching books: ', error);
        res.status(500).json({error: 'Internal server error'});
    } 
};

// Get All Available Books
export const getAvailableBooks = async(req: Request, res: Response) => {
    try {
        const result = await pool.query('SELECT * FROM books WHERE is_available = true');
        res.json(result.rows);
    } catch(error){
        console.error('Error fetching books: ', error);
        res.status(500).json({error: 'Internal server error'});
    } finally {
        pool.end();
    }
};
