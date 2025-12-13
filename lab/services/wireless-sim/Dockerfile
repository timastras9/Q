FROM kalilinux/kali-rolling

# Install wireless tools and password crackers
RUN apt-get update && apt-get install -y \
    hostapd \
    dnsmasq \
    aircrack-ng \
    hashcat \
    john \
    hydra \
    medusa \
    ncrack \
    wordlists \
    wifite \
    cowpatty \
    freeradius \
    python3-scapy \
    tcpdump \
    tshark \
    && apt-get clean

# Create capture directory for handshakes
RUN mkdir -p /captures /wordlists /hashes

# Copy configuration and scripts
COPY hostapd.conf /etc/hostapd/hostapd.conf
COPY dnsmasq.conf /etc/dnsmasq.conf
COPY radius/ /etc/freeradius/3.0/
COPY scripts/ /opt/scripts/
COPY sample-hashes/ /hashes/
COPY wordlists/ /wordlists/

RUN chmod +x /opt/scripts/*.sh

# Expose ports
EXPOSE 80 443 1812/udp 1813/udp

CMD ["/opt/scripts/start-wireless-sim.sh"]
