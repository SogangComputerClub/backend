# Stage 1: Build the application
FROM node:20-alpine AS builder

WORKDIR /app

# Copy dependency definitions
COPY package*.json ./
ARG CACHEBUST=1
RUN echo "Cache bust: $CACHEBUST"
# Install dependencies (including dev dependencies)
RUN npm install

# Copy the rest of the source code
COPY . .

RUN rm -rf dist
# Remove any existing dist directory (optional, ensures a clean build)

# Compile the TypeScript code (only compiles, does not start the server)
RUN npm run build

# Stage 2: Set up the production environment
FROM node:20-alpine

WORKDIR /app

# Copy dependency definitions
COPY package*.json ./

# Install only production dependencies
RUN npm install --production

# Copy the built application from the builder stage
COPY --from=builder /app/dist ./dist

# Copy additional files (e.g., swagger.yaml)
COPY --from=builder /app/src/config/swagger.yaml ./dist/config/swagger.yaml

# Expose the application port
EXPOSE 3000

# Start the application
CMD ["npm", "run", "start"]