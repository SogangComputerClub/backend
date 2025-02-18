import 'dotenv/config'; //-> 필요 없다길래 없앰. 해보니까 실제로 필요 없었음.
import express, { Request, Response } from 'express';
import swaggerUi from 'swagger-ui-express';
import swaggerJsdoc from 'swagger-jsdoc';
import path from 'path'; // Import path module
import { initializeAuth } from './middlewares/auth';
import { initializeRedis } from './middlewares/redis';
import authRouter from './routes/auth';
import protectedRouter from './routes/protected_hello';
import fs from 'fs';
import yaml from 'js-yaml';
//import authRouter from './routes/users';
//import protectedRouter from './routes/protected_hello';

import booksRouter from './routes/book';

const SECRET_KEY: string = process.env.JWT_SECRET!;

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
        url: `http://${HOST}:${PORT}`,
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
  apis: [path.join(__dirname, '**/*.ts')], // Adjust based on your project structure
};
// if dev environment, export to config/swagger.yaml
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
(async ()=>initializeRedis())();

// Serve Swagger UI
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec as swaggerUi.JsonObject));

// router
app.use('/api/v1', booksRouter); // /api/v1/allbooks 경로에서 사용
app.use('/api/v1/auth', authRouter);
app.use('/api/v1/protected', protectedRouter);

// Start the server
app.listen(PORT, () => {
  console.log(`Server running at http://${HOST}:${PORT}`);
  console.log(`Swagger docs available at http://${HOST}:${PORT}/api-docs`);
});
