FROM node:16

WORKDIR /app

COPY app/package*.json ./
RUN npm install

COPY app/server.js ./

EXPOSE 80/tcp 443/tcp
VOLUME /data
CMD [ "node", "server.js" ]
