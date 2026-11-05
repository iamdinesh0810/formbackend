FROM node:22-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY server.js ./
ENV NODE_ENV=production
VOLUME /app/data
EXPOSE 3000
CMD ["node", "server.js"]
