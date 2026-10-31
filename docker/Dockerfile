FROM node:22-alpine

# openssl creates the keys and certificates; su-exec drops root after fixing ownership
RUN apk add --no-cache openssl su-exec tini

# Llar has no npm dependencies, only Node's standard library
COPY web /opt/llar
RUN chmod 755 /opt/llar/entrypoint.sh

ENV NODE_ENV=production \
    PORT=3000 \
    LLAR_DATA=/llar

EXPOSE 3000
VOLUME /llar

# The entrypoint starts as root to fix /llar ownership, then runs Llar as
# uid/gid 1000 (the node image's "node" user, like Umbrel's app data).
ENTRYPOINT ["/sbin/tini", "--", "/opt/llar/entrypoint.sh"]
CMD ["node", "/opt/llar/server.js"]
