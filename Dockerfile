# Use a base image with Python and development tools
FROM python:3.13-slim

# Set the working directory
WORKDIR /app

# Copy the files required for installation
COPY pyproject.toml .
COPY src/ ./src/

RUN pip install . --no-cache-dir

# Optional: bake FossID Toolbox into the image (blind-scan / analyze).
# 1. Download the Linux binary from FossID Vault
# 2. Place it in this repo as ./fossid-toolbox
# 3. Uncomment the two lines below and run: docker build -t workbench-agent-ce:latest .
# See the wiki page "Container Image with Toolbox".
# COPY fossid-toolbox /usr/local/bin/fossid-toolbox
# RUN chmod +x /usr/local/bin/fossid-toolbox

ENTRYPOINT [ "workbench-agent" ]