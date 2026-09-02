# Use a base image with Python and development tools
FROM python:3.13-slim

# Set the working directory
WORKDIR /app

# Copy the files required for installation
COPY pyproject.toml .
COPY src/ ./src/

RUN pip install . --no-cache-dir

# Optional: bake FossID Toolbox into the image (blind-scan / analyze).
# For instructions, see the wiki page "Container Image with Toolbox".
# COPY toolbox/fossid-toolbox /usr/local/bin/fossid-toolbox
# COPY toolbox/fossid.conf /usr/local/bin/fossid.conf
# RUN chmod +x /usr/local/bin/fossid-toolbox

ENTRYPOINT [ "workbench-agent" ]