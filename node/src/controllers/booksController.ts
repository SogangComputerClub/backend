import type { Request, Response } from "express";
import { pool } from "../middlewares/db.js";
import type { BookInfo } from "../types/book.d.ts";
import validator from "validator";

export const getBook = async (req: Request, res: Response): Promise<void> => {
  const { available, author, title } = req.query as {
    available?: string;
    author?: string;
    title?: string;
  };

  let availableParsed: boolean | undefined;
  if (available !== undefined) {
    const lower = available.toLowerCase();
    if (lower === "true" || lower === "false") {
      availableParsed = lower === "true";
    } else {
      res.status(400).json({
        error:
          "Invalid 'available' query parameter. Expected 'true' or 'false'.",
      });
      return;
    }
  }

  const authorParsed: string | undefined = author;
  const titleParsed: string | undefined = title;

  let query = "SELECT * FROM books";
  const params: (boolean | string)[] = [];

  if (availableParsed !== undefined) {
    query += params.length > 0 ? " AND" : " WHERE";
    query += " is_available = $" + (params.length + 1);
    params.push(availableParsed);
  }

  if (authorParsed) {
    query += params.length > 0 ? " AND" : " WHERE";
    query += " author ILIKE '%' || $" + (params.length + 1) + " || '%'";
    params.push(authorParsed);
  }

  if (titleParsed) {
    query += params.length > 0 ? " AND" : " WHERE";
    query += " title ILIKE '%' || $" + (params.length + 1) + " || '%'";
    params.push(titleParsed);
  }

  console.debug("Executing query:", query, params);

  try {
    const result = await pool.query(query, params);
    const books: BookInfo[] = result.rows;
    res.json(books);
  } catch (error) {
    console.error("Error fetching books:", error);
    res.status(500).json({ error: "Internal server error" });
  }
};

export const getBookById = async (
  req: Request,
  res: Response,
): Promise<void> => {
  const { id } = req.params as { id: string };
  if (!validator.isInt(id)) {
    res.status(400).json({ error: "Invalid book id" });
    return;
  }
  const bookId = Number(id);

  try {
    const result = await pool.query("SELECT * FROM books WHERE book_id = $1", [
      bookId,
    ]);
    if (result.rows.length > 0) {
      const book: BookInfo = result.rows[0];
      res.json(book);
    } else {
      res.status(404).json({ error: "Book not found" });
    }
  } catch (error) {
    console.error("Error fetching book by ID:", error);
    res.status(500).json({ error: "Internal server error" });
  }
};

export const borrowBookAny = async (book_id: number, borrower: string): Promise<boolean> => {
  const result = await pool.query(
    "SELECT is_available, num_available FROM books WHERE book_id = $1;",
    [book_id]
  );

  if (result.rows.length === 0 || !(result.rows[0].is_available)){
    console.debug("Not Available");
    return false;
  } 
  const availableCopy = result.rows.find((row) => row.book_status === true);

  await pool.query(
    "UPDATE book_copy SET book_status = FALSE, borrower = $1 WHERE copy_id = $2;",
    [borrower, availableCopy.copy_id]
  );

  const newNumCopies = result.rows[0].num_available - 1;
  const availability = !(newNumCopies === 0);  

  await pool.query(
    "UPDATE books SET num_available = $1, is_available = $2;",
    [newNumCopies, availability]
  );

  return true;
};

export const borrowBookByID = async (copy_id: number, borrower: string): Promise<boolean> => {
  const result = await pool.query(
    "SELECT book_status FROM book_copy WHERE copy_id = $1;",
    [copy_id]
  );

  if (result.rows.length === 0 || !result.rows[0].status) {
    console.debug("Not available");
    return false;
  }

  await pool.query(
    "UPDATE book_copy SET book_status = FALSE, borrower = $1 WHERE copy_id = $2;",
    [borrower, copy_id]
  );

  const availableCopy = result.rows.find((row) => row.book_status === true);  

  const books = await pool.query(
    "SELECT num_available FROM books WHERE book_id = $1;",
    [result.rows[0].book_id]
  );
  const num_available = books.rows[0].num_available - 1;
  
  await pool.query(
    "UPDATE books SET is_available = $1, num_available = $2",
    [!(num_available === 0), num_available]
  );

  return true;
};

export const returnBookByAny = async () => {

};