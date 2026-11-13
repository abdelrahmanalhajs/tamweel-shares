FROM node:22-alpine
WORKDIR /app
COPY package.json server.js index.html ./
ENV NODE_ENV=production TRUST_PROXY=1 DB_PATH=/data/tamweel.db PORT=3000
VOLUME /data
EXPOSE 3000
CMD ["node","server.js"]
