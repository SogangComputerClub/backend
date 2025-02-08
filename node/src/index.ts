import 'dotenv/config';
import express, { Request, Response } from 'express';
import swaggerUi from 'swagger-ui-express';
import swaggerJsdoc from 'swagger-jsdoc';
import path from 'path'; // Import path module
import { pool } from './middlewares/db';
import passport from 'passport';
import jwt from 'jsonwebtoken';
import { initializeAuth} from './auth';
import fs from 'fs';
import yaml from 'js-yaml';
import authRouter from './routes/users';

const SECRET_KEY: string = process.env.JWT_SECRET!;

const app = express();
app.use(express.json());
app.use(initializeAuth());

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
        url: `http://${HOST}:${PORT}`,
      },
    ],
  },
  apis: [path.join(__dirname, '**/*.ts')], // Adjust based on your project structure
};

// Generate Swagger Spec
const swaggerSpec = swaggerJsdoc(swaggerOptions);

// Debug: Log the Swagger Spec to verify
console.log('Generated Swagger Specification:', JSON.stringify(swaggerSpec, null, 2));

// Serve Swagger UI
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

// router
app.use('/api/v1/auth', authRouter);

// Start the server
app.listen(PORT, () => {
  console.log(`Server running at http://${HOST}:${PORT}`);
  console.log(`Swagger docs available at http://${HOST}:${PORT}/api-docs`);
});
