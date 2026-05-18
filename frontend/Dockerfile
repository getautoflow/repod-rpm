# Étape 1 : Build de React
FROM node:18 AS build
WORKDIR /app

# L'URL de l'API est injectée au moment du build
ARG REACT_APP_API_URL=http://localhost:8000
ENV REACT_APP_API_URL=$REACT_APP_API_URL

ARG REACT_APP_REPO_URL=http://localhost:80
ENV REACT_APP_REPO_URL=$REACT_APP_REPO_URL

COPY package.json package-lock.json ./
RUN npm install
COPY . .
RUN npm run build

# Étape 2 : Serveur Nginx
FROM nginx:alpine
COPY --from=build /app/build /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
