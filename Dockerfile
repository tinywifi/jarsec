FROM eclipse-temurin:21-jdk

LABEL org.opencontainers.image.source="https://github.com/tinywifi/jarsec"
LABEL org.opencontainers.image.description="Jarsec malware analysis sandbox with Minecraft, video recording, and network capture"
LABEL org.opencontainers.image.licenses="MIT"

# Install everything in one RUN to minimize layers
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends \
        python3-pip \
        python3 \
        xvfb \
        libgl1 \
        libgl1-mesa-dri \
        libpulse0 \
        libxrandr2 \
        libxss1 \
        libxcursor1 \
        libxinerama1 \
        libxi6 \
        tcpdump \
        tshark \
        strace \
        lsof \
        net-tools \
        iproute2 \
        curl \
        wget \
        ffmpeg \
        fonts-dejavu-core \
        inotify-tools \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --break-system-packages --no-cache-dir portablemc \
    && mkdir -p /root/.minecraft/mods \
    && mkdir -p /root/.jarsec/decompilers \
    && mkdir -p /root/.config/discord/Local\ Storage/leveldb \
    && mkdir -p /tmp/recordings

WORKDIR /root

# Pre-install decompilers into the image so they don't need downloading every run
RUN curl -sL -o /root/.jarsec/decompilers/vineflower.jar \
    "https://github.com/Vineflower/vineflower/releases/download/1.12.0/vineflower-1.12.0.jar" \
    && curl -sL -o /root/.jarsec/decompilers/cfr.jar \
    "https://github.com/leibnitz27/cfr/releases/download/0.152/cfr-0.152.jar"

ENV DISPLAY=:99
ENV _JAVA_OPTIONS="-Djava.awt.headless=false"
