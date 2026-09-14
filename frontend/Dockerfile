FROM node:22-alpine AS builder

WORKDIR /app

COPY package.json package-lock.json* ./
# No lockfile in the repo, so fall back to a plain install.
RUN npm ci 2>/dev/null || npm install

COPY . .

ARG VITE_API_BASE_URL=http://localhost:8080
ENV VITE_API_BASE_URL=${VITE_API_BASE_URL}

RUN npm run build

FROM nginx:1.27-alpine AS runtime

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=builder /app/dist /usr/share/nginx/html

EXPOSE 80

HEALTHCHECK --interval=10s --timeout=5s --retries=6 \
    CMD wget -qO- http://localhost/ >/dev/null 2>&1 || exit 1
