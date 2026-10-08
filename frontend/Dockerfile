# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM node:24-alpine@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1

WORKDIR /app
COPY package.json package-lock.json ./
RUN chown node:node /app
USER node
RUN npm ci && npm cache clean --force
USER root
RUN rm -rf /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx
COPY --chown=node:node . .

USER node
EXPOSE 5173
CMD ["node", "node_modules/vite/bin/vite.js", "--host", "0.0.0.0"]
