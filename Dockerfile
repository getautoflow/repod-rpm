FROM nginx:1.27.4-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    createrepo-c \
    gnupg \
    && rm -rf /var/lib/apt/lists/*

# Structure du dépôt RPM accessible via nginx
RUN mkdir -p /usr/share/nginx/html/repos

COPY nginx/repo.conf /etc/nginx/conf.d/repo.conf
COPY scripts/init-repo.sh /init-repo.sh
RUN chmod +x /init-repo.sh

EXPOSE 80

CMD ["/bin/bash", "-c", "/init-repo.sh && nginx -g 'daemon off;'"]
