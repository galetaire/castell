FROM node:22-alpine

# openssl creates the keys and certificates; su-exec drops root after fixing ownership
RUN apk add --no-cache openssl su-exec tini

# Castell has no npm dependencies, only Node's standard library
COPY web /opt/castell
RUN chmod 755 /opt/castell/entrypoint.sh

ENV NODE_ENV=production \
    PORT=3000 \
    CASTELL_DATA=/castell

EXPOSE 3000
VOLUME /castell

# The entrypoint starts as root to fix /castell ownership, then runs Castell as
# uid/gid 1000 (the node image's "node" user, like Umbrel's app data).
ENTRYPOINT ["/sbin/tini", "--", "/opt/castell/entrypoint.sh"]
CMD ["node", "/opt/castell/server.js"]
