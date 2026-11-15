# syntax=docker/dockerfile:1
# Proof Gatekeeper — multi-stage image (Node 24, no Express, snarkjs only).
# Circuit binaries are downloaded from the official Agent Games artifacts
# at build time and verified by sha256 (they are not stored in the repo).

FROM node:24-alpine AS build
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json ./
COPY src ./src
COPY scripts ./scripts
COPY test ./test
RUN npm run build

FROM node:24-alpine AS runtime
WORKDIR /app
ENV NODE_ENV=production
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --from=build /app/dist ./dist
COPY circuits/verification_key.json ./circuits/verification_key.json
RUN apk add --no-cache curl \
 && cd circuits \
 && curl -sSL -o gatekeeper.wasm https://agentgames.zkverify.io/circuits/gatekeeper.wasm \
 && curl -sSL -o gatekeeper_final.zkey https://agentgames.zkverify.io/circuits/gatekeeper_final.zkey \
 && echo "be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f  gatekeeper.wasm" | sha256sum -c - \
 && echo "adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d  gatekeeper_final.zkey" | sha256sum -c - \
 && apk del curl
EXPOSE 3000
CMD ["node", "dist/src/index.js"]
