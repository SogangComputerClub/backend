import 'dotenv/config';
import { Request, Response } from 'express';
import { pool } from '../middlewares/db';

export const getBook = async (req: Request, res: Response) => {
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

export const getBookById = async (req: Request, res: Response) => {
    const { id } = req.params;

    try {
        const result = await pool.query('SELECT * FROM books WHERE book_id = $1', [id]);
        if (result.rows.length > 0) {
            res.json(result.rows[0]);
        } else {
            res.status(404).json({ error : 'Book not found'});
        }
    } catch (error) {
        console.error('Error fetching book by ID:', error);
        res.status(400).json({ error: 'Internal server error'});
    }
};