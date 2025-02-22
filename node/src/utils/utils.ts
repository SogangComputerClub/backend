import { fileURLToPath } from 'url';
import path from 'path'; // Import path module

const __filename = fileURLToPath(import.meta.url);

export const __dirname = path.resolve(path.dirname(__filename), './../');