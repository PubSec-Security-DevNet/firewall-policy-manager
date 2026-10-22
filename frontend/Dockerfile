# Copyright 2026 Cisco Systems, Inc.
# SPDX-License-Identifier: Apache-2.0
FROM node:24-alpine@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53

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
