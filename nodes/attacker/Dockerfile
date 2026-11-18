FROM kalilinux/kali-rolling
ARG HTTP_PROXY
ARG HTTPS_PROXY
ARG http_proxy
ARG https_proxy
ARG NO_PROXY

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      bash ca-certificates curl git jq \
      iproute2 iptables iputils-ping dnsutils \
      nmap masscan nikto rustscan arp-scan \
      tshark tcpdump ngrep \
      python3 python3-scapy \
      hydra john sshpass openssh-client \
      procps less vim \
    && rm -rf /var/lib/apt/lists/*

RUN echo 'root:lab' | chpasswd
WORKDIR /root
CMD ["/bin/bash"]
