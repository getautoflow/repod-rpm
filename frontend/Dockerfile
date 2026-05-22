# Étape 1 : Build de React
FROM node:18 AS build
WORKDIR /app

# URL de l'API — vide = URLs relatives (nginx proxifie /api/ vers le backend)
# Passer --build-arg REACT_APP_API_URL=http://... pour un accès direct cross-origin
ARG REACT_APP_API_URL=
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
