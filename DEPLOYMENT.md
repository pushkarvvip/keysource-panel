# Deployment

This repo is configured to run the `bgmi-mod-system` app from the repository root.

## Railway

1. Connect the repo to Railway.
2. Railway will use the `Dockerfile` in the repo root.
3. Set any needed environment variables.
4. If you want SQLite data to persist, mount a volume and set `DB_PATH` to that mounted path.

Recommended env vars:

- `PORT=3000`
- `HOST=0.0.0.0`
- `DB_PATH=/data/database.sqlite`

## VPS

1. Install Docker on the VPS.
2. Build the image from the repo root.
3. Run the container and map port 3000.
4. Mount a persistent volume for the SQLite database if you want data to survive restarts.

Example:

```bash
docker build -t bgmi-mod-system .
docker run -d \
  -p 3000:3000 \
  -e PORT=3000 \
  -e HOST=0.0.0.0 \
  -e DB_PATH=/data/database.sqlite \
  -v /opt/bgmi-data:/data \
  --name bgmi-mod-system \
  bgmi-mod-system
```