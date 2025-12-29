
FROM node:20-alpine

WORKDIR /app

COPY package*.json ./

RUN npm install

# Copy application files
COPY . .

EXPOSE 8000

# Start the application
CMD ["npm", "start"]
