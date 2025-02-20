import { Request, Response } from 'express';
import { pool } from '../middlewares/db';

export interface BookInfo {
  book_id : number;
  title : string;
  author : string;
  is_available : boolean;
}
export const getBook = async (req: Request, res: Response): Promise<void> => {
  const { available, author, title } = req.query as { 
    available?: string; 
    author?: string; 
    title?: string;
  };

  let availableParsed: boolean | undefined;
  if (available !== undefined) {
    const lower = available.toLowerCase();
    if (lower === 'true' || lower === 'false') {
      availableParsed = lower === 'true';
    } else {
      res.status(400).json({ error: "Invalid 'available' query parameter. Expected 'true' or 'false'." });
      return;
    }
  }

  const authorParsed: string | undefined = author;
  const titleParsed: string | undefined = title;

  let query = 'SELECT * FROM books';
  const params: any[] = [];

  if (availableParsed !== undefined) {
    query += params.length > 0 ? ' AND' : ' WHERE';
    query += ' is_available = $' + (params.length + 1);
    params.push(availableParsed);
  }

  if (authorParsed) {
    query += params.length > 0 ? ' AND' : ' WHERE';
    query += " author ILIKE '%' || $" + (params.length + 1) + " || '%'";
    params.push(authorParsed);
  }

  if (titleParsed) {
    query += params.length > 0 ? ' AND' : ' WHERE';
    query += " title ILIKE '%' || $" + (params.length + 1) + " || '%'";
    params.push(titleParsed);
  }

  console.debug('Executing query:', query, params);

  try {
    const result = await pool.query(query, params);
    const books: BookInfo[] = result.rows;
    res.json(books);
  } catch (error) {
    console.error('Error fetching books:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};

export const getBookById = async (req: Request, res: Response): Promise<void> => {
  const { id } = req.params as { id: string };
  const bookId = Number(id);

  if (isNaN(bookId)) {
    res.status(400).json({ error: 'Invalid book id' });
    return;
  }

  try {
    const result = await pool.query('SELECT * FROM books WHERE book_id = $1', [bookId]);
    if (result.rows.length > 0) {
      const book: BookInfo = result.rows[0];
      res.json(book);
    } else {
      res.status(404).json({ error: 'Book not found' });
    }
  } catch (error) {
    console.error('Error fetching book by ID:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
};
