FROM node:12

WORKDIR /app

RUN mkdir -p /etc/letsencrypt/live/zep-kkutu.online

COPY ./etc/letsencrypt/live/zep-kkutu.online /etc/letsencrypt/live/zep-kkutu.online

COPY ./Server/setup.js ./Server/
COPY ./Server/package*.json ./Server/
COPY ./Server/lib/package*.json ./Server/lib/
COPY ./Server/lib/ ./Server/lib/
COPY ./Server/etc/ ./Server/etc/

RUN chmod a+r /etc/letsencrypt/live/zep-kkutu.online

RUN cd Server && node setup

RUN cd Server/lib && npx grunt default pack

WORKDIR /kkutu