FROM node:20-slim
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY . .
EXPOSE 3402
ENV PORT=3402
CMD ["node", "index.js"]
