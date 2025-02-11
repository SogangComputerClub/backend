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
    }
};
export const getBooks = async (req: Request, res: Response) => {
    const { available, author } = req.query;
    let query = 'SELECT * FROM books';
    const params: any[] = [];
  
    if (available !== undefined) {
      query += params.length > 0 ? ' AND' : ' WHERE';
      query += ' is_available = $' + (params.length + 1);
      params.push(available === 'true');
    }
  
    if (author) {
      query += params.length > 0 ? ' AND' : ' WHERE';
      query += ' author = $' + (params.length + 1);
      params.push(author);
    }
  
    console.log('Executing query:', query, params); // 디버그용 로그
    try {
      const result = await pool.query(query, params);
      res.json(result.rows);
    } catch (error) {
      console.error('Error fetching books:', error);
      res.status(500).json({ error: 'Internal server error' });
    }
};
  