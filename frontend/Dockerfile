# =============================================================================
# Multi-stage Dockerfile for Network Device Backup Management System - Frontend
# =============================================================================
# Stage 1: Build React application
# Stage 2: Serve with nginx
# Security: Non-root user, minimal nginx configuration, security headers
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Builder - Build React application
# -----------------------------------------------------------------------------
FROM node:18-alpine as builder

# Set working directory
WORKDIR /build

# Copy package files
COPY package.json package-lock.json ./

# Install dependencies with clean npm cache
RUN npm ci --only=production && \
    npm cache clean --force

# Copy source code
COPY . .

# Build production-optimized bundle
ENV NODE_ENV=production
RUN npm run build

# -----------------------------------------------------------------------------
# Stage 2: Runtime - Nginx web server
# -----------------------------------------------------------------------------
FROM nginx:1.25-alpine

# Metadata labels
LABEL maintainer="vichai.saisood@gmail.com"
LABEL description="Network Device Backup Management System - Frontend"
LABEL version="1.0.0"

# Remove default nginx configuration
RUN rm -rf /etc/nginx/conf.d/default.conf

# Copy custom nginx configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy built application from builder
COPY --from=builder /build/build /usr/share/nginx/html

# Create non-root user for nginx
RUN addgroup -g 1000 -S appuser && \
    adduser -u 1000 -S appuser -G appuser && \
    chown -R appuser:appuser /usr/share/nginx/html && \
    chown -R appuser:appuser /var/cache/nginx && \
    chown -R appuser:appuser /var/log/nginx && \
    touch /var/run/nginx.pid && \
    chown -R appuser:appuser /var/run/nginx.pid

# Update nginx to run as non-root user
RUN sed -i 's/user  nginx/user  appuser/g' /etc/nginx/nginx.conf

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 80

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost/ || exit 1

# Start nginx
CMD ["nginx", "-g", "daemon off;"]
