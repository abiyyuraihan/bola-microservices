FROM node:20-alpine
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY shared ./shared
COPY services ./services
USER node
EXPOSE 3000
CMD ["node", "services/api-gateway/src/index.js"]
