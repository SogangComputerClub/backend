import 'dotenv/config';
import express from 'express';
import swaggerUi from 'swagger-ui-express';
import swaggerJsdoc from 'swagger-jsdoc';
import { initializeAuth } from './middlewares/auth.js';
import { initializeRedis } from './middlewares/redis.js';
import fs from 'fs';
import yaml from 'js-yaml';
import { __dirname } from './utils/utils.js';
import path from 'path';
import authRouter from './routes/auth.js';
import protectedRouter from './routes/protected_hello.js';
import booksRouter from './routes/book.js';

const app = express();
// Port and Host
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || 'localhost';

// Swagger options with absolute path and glob pattern
const swaggerOptions: swaggerJsdoc.Options = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Library API',
      version: '1.0.0',
      description: 'API documentation',
    },
    servers: [
      {
        url: `http://${HOST}:${PORT}/api/v1`,
      },
    ],
    tags: [
      {
        name: 'Users',
        description: 'User operations',
      },
      {
        name: 'Protected',
        description: 'Protected routes',
      },
    ],
    components: {
      securityDefinitions: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        },
      },
      securitySchemes: {
        bearerAuth: {
          type: 'http',
          scheme: 'bearer',
          bearerFormat: 'JWT',
        }
      },
    },
  },
  apis: [path.join(__dirname, '**/*.ts')],
};

if (process.env.NODE_ENV !== 'production') {
  const swaggerDoc = swaggerJsdoc(swaggerOptions);
  fs.mkdirSync('src/config', { recursive: true }); // Ensure directory exists
  fs.writeFileSync(path.join(__dirname, 'config', 'swagger.yaml'), yaml.dump(swaggerDoc));
}

const swaggerSpec = process.env.NODE_ENV === 'production' 
  ? yaml.load(fs.readFileSync(path.join(__dirname, 'config', 'swagger.yaml'), 'utf8'))
  : swaggerJsdoc(swaggerOptions);

// Debug: Log the Swagger Spec to verify
console.log('Generated Swagger Specification:', JSON.stringify(swaggerSpec, null, 2));
app.use(express.json());
app.use(initializeAuth());
await initializeRedis();
// Serve Swagger UI
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec as swaggerUi.JsonObject));

// router
app.use('/api/v1', booksRouter);
app.use('/api/v1/auth', authRouter);
app.use('/api/v1/protected', protectedRouter);

// Start the server
app.listen(PORT, () => {
  console.log(`Server running at http://${HOST}:${PORT}`);
  console.log(`Swagger docs available at http://${HOST}:${PORT}/api-docs`);
});
