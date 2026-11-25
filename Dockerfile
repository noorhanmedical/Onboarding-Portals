# Plexus Onboarding Portal — production image (AWS App Runner, ECS, or any container host)
FROM public.ecr.aws/docker/library/node:20-alpine
WORKDIR /app
ENV NODE_ENV=production PORT=3000
# Amazon RDS certificate bundle so the database connection is verified TLS.
ADD https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem /app/rds-ca.pem
COPY package.json package-lock.json ./
RUN npm ci --omit=dev && npm cache clean --force && chmod 644 /app/rds-ca.pem
COPY server.js ./
COPY public ./public
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD wget -qO- http://127.0.0.1:3000/healthz || exit 1
CMD ["node", "server.js"]
