CREATE TABLE IF NOT EXISTS books (
  book_id SERIAL PRIMARY KEY,
  title VARCHAR(255) NOT NULL,
  author VARCHAR(255) NOT NULL,
  genre VARCHAR(255) NOT NULL,
  publication_year CHAR(4),
  is_available BOOLEAN NOT NULL,
  isbn CHAR(13) UNIQUE
);

CREATE TABLE IF NOT EXISTS users (
  user_id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  username VARCHAR(255) NOT NULL,
  password VARCHAR(255) NOT NULL
);

CREATE FUNCTION generate_isbn(publisher_code CHAR(7), book_id INT) RETURNS CHAR(13)
BEGIN
    DECLARE isbn CHAR(13);
    DECLARE sum INT DEFAULT 0;
    DECLARE checksum INT;
    DECLARE i INT;

    -- 기본 ISBN 생성 (출판사 코드 + 도서 ID 조합)
    SET isbn = CONCAT(publisher_code, LPAD(book_id, 5, '0'));

    -- 체크 디지트 계산
    SET i = 1;
    WHILE i <= 12 DO
        IF MOD(i, 2) = 1 THEN
            SET sum = sum + CAST(SUBSTRING(isbn, i, 1) AS UNSIGNED);
        ELSE
            SET sum = sum + CAST(SUBSTRING(isbn, i, 1) AS UNSIGNED) * 3;
        END IF;
        SET i = i + 1;
    END WHILE;

    SET checksum = (10 - (sum % 10)) % 10;
    RETURN CONCAT(isbn, checksum);
END

CREATE TRIGGER validate_isbn BEFORE INSERT ON books
FOR EACH ROW
BEGIN
    DECLARE sum INT DEFAULT 0;
    DECLARE checksum INT;
    DECLARE i INT;

    SET i = 1;
    -- ISBN-13 유효성 검사
    WHILE i <= 12 DO
        IF MOD(i, 2) = 1 THEN
            SET sum = sum + CAST(SUBSTRING(NEW.isbn, i, 1) AS UNSIGNED);
        ELSE
            SET sum = sum + CAST(SUBSTRING(NEW.isbn, i, 1) AS UNSIGNED) * 3;
        END IF;
        SET i = i + 1;
    END WHILE;

    SET checksum = (10 - (sum % 10)) % 10;

    -- 체크 디지트 확인
    IF checksum != CAST(SUBSTRING(NEW.isbn, 13, 1) AS UNSIGNED) THEN
        SIGNAL SQLSTATE '45000'
        SET MESSAGE_TEXT = 'Invalid ISBN-13 checksum';
    END IF;
END

INSERT INTO books (title, author, genre, publication_year, is_available, isbn)
VALUES 
  ('The Great Gatsby', 'F. Scott Fitzgerald', 'Novel', '1925', TRUE, generate_isbn('9783161', 1)),
  ('To Kill a Mockingbird', 'Harper Lee', 'Novel', '1960', TRUE, generate_isbn('9783161', 2)),
  ('1984', 'George Orwell', 'Novel', '1949', FALSE, generate_isbn('9783161', 3)),
  ('Pride and Prejudice', 'Jane Austen', 'Novel', '1813', TRUE, generate_isbn('9783161', 4)),
  ('Moby-Dick', 'Herman Melville', 'Novel', '1851', FALSE, generate_isbn('9783161', 5))