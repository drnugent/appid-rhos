FROM node:latest

WORKDIR /appid-rhos

COPY package.json ./

RUN npm install

COPY . .

CMD ["npm", "start"]