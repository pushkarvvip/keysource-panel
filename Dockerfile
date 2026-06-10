FROM node:24-bullseye-slim

WORKDIR /app

COPY bgmi-mod-system/package*.json ./bgmi-mod-system/
RUN cd bgmi-mod-system && npm install --omit=dev

COPY . .

ENV NODE_ENV=production
ENV PORT=3000
ENV HOST=0.0.0.0

WORKDIR /app/bgmi-mod-system

EXPOSE 3000

CMD ["node", "server.js"]