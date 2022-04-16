FROM python:3.10-slim-bullseye
LABEL maintainer="Kevin Kuusela (Codekuu) codekuu@oppetinternet.se"
ENV PYTHONDONTWRITEBYTECODE 1

# Updating and installing git
RUN apt-get update && \
    apt-get install -y git curl wget

# INSTALL GITLEAKS
RUN curl -s  https://api.github.com/repos/zricethezav/gitleaks/releases/latest | grep browser_download_url  |  cut -d '"' -f 4  | grep 'linux_x64' | wget -i -
RUN tar -xf gitleaks_*_linux_x64.tar.gz
RUN mv gitleaks /usr/bin/

# Change dir and copy project.
COPY . /

# Creating and install venv
RUN python3.10 -m pip install --upgrade pip
RUN python3.10 -m pip install -r requirements.txt

# Change to the binded volume
WORKDIR /opt/gitlab-scanner

ENTRYPOINT ["python3.10", "/gitlab-scanner.py"]