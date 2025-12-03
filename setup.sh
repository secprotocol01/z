#!/bin/bash
set -e

LOGFILE=/var/log/hardening.log

log() {
    echo "[+] $1"
    echo "[+] $1" >> "$LOGFILE"
}

###########################################################
### KILL-SWITCH – vypne SELinux enforcing, firewall, Tor, auditd
###########################################################
if [[ "$1" == "off" ]]; then
    log "Kill-switch: disabling hardening..."

    setenforce 0 || true
    systemctl stop nftables || true
    systemctl stop auditd || true
    systemctl stop tor || true

    log "All protections disabled. System ready for MITM, WiFi hacking, injection."
    exit 0
fi

###########################################################
### 1) SELinux MLS
###########################################################
log "Enabling SELinux MLS mode..."

sed -i 's/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config
sed -i 's/^SELINUXTYPE=.*/SELINUXTYPE=mls/' /etc/selinux/config

# Aircrack-ng, Scapy, monitor-mode → unconfined
semanage permissive -a unconfined_t 2>/dev/null || true

###########################################################
### 2) Kernel Hardening
###########################################################
log "Applying kernel hardening..."

cat >/etc/sysctl.d/99-hardening.conf <<EOF
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
kernel.unprivileged_bpf_disabled=1
kernel.yama.ptrace_scope=3
kernel.kexec_load_disabled=1
kernel.kmod_lock=1
kernel.sysrq=0
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.all.log_martians=1
EOF

sysctl --system

###########################################################
### 3) nftables – strict whitelist
###########################################################
log "Configuring nftables whitelist..."

cat >/etc/nftables.conf <<'EOF'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
 chain input {
   type filter hook input priority 0;

   # loopback
   iif lo accept

   # established
   ct state established,related accept

   # SSH for admin
   tcp dport 22 accept

   # DNS (DNSCrypt)
   udp dport 53 accept

   # Tor transparent
   tcp dport 9040 accept
   udp dport 5353 accept

   # default drop
   drop
 }
}
EOF

systemctl enable --now nftables

###########################################################
### 4) auditd – Neo23x0 rules
###########################################################
log "Installing auditd with Neo23x0 rules..."

dnf install -y audit audit-libs

curl -s -L \
 https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules \
 -o /etc/audit/rules.d/neo23x0.rules || true

# Load rules
augenrules --load
systemctl enable --now auditd

###########################################################
### 5) AIDE integrity monitoring
###########################################################
log "Initializing AIDE..."

dnf install -y aide
aide --init

mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

###########################################################
### 6) SSH Hardening (FIPS-like)
###########################################################
log "Hardening SSH..."

cat >/etc/ssh/sshd_config.d/harden.conf <<EOF
PasswordAuthentication no
Ciphers aes256-gcm@openssh.com,chacha20-poly1305@openssh.com
KexAlgorithms curve25519-sha256
MACs hmac-sha2-512
EOF

systemctl restart sshd

###########################################################
### 7) Tor Transparent Routing
###########################################################
log "Installing and configuring Tor Transparent Mode..."

dnf install -y tor

cat >/etc/tor/torrc <<EOF
RunAsDaemon 1
AutomapHostsOnResolve 1
TransPort 9040
DNSPort 5353
VirtualAddrNetworkIPv4 10.192.0.0/10
EOF

# Redirect system traffic → Tor
iptables -t nat -A OUTPUT -m owner ! --uid-owner tor -p tcp -j REDIRECT --to-ports 9040
iptables -t nat -A OUTPUT -m owner ! --uid-owner tor -p udp --dport 53 -j REDIRECT --to-ports 5353

systemctl enable --now tor

###########################################################
### 8) DNSCrypt
###########################################################
log "Installing DNSCrypt-proxy..."

dnf install -y dnscrypt-proxy

systemctl enable --now dnscrypt-proxy

rm -f /etc/resolv.conf
echo "nameserver 127.0.0.1" >/etc/resolv.conf

###########################################################
### 9) WireGuard + strongSwan
###########################################################
log "Installing VPN stack (WG + strongSwan)..."

dnf install -y wireguard-tools strongswan

###########################################################
### 10) Disable telemetry
###########################################################
log "Disabling RHEL telemetry..."

systemctl disable --now insights-client || true
systemctl disable --now abrt || true
systemctl disable --now packagekit || true

echo "[+] Installing OSINT tools..."
git clone https://github.com/soxoj/maigret
pip3 install -r maigret/requirements.txt

git clone https://github.com/Lissy93/web-check
git clone https://github.com/tejado/telegram-nearby-map
git clone https://github.com/megadose/holehe
pip3 install holehe

git clone https://github.com/Ullaakut/cameradar
git clone https://github.com/bee-san/Ciphey
pip3 install ciphey

git clone https://github.com/commixproject/commix

git clone https://github.com/jonaslejon/malicious-pdf
git clone https://github.com/n1nj4sec/pupy
pip3 install evil-winrm 
git clone https://github.com/BloodHoundAD/BloodHound.git
pip3 install crackmapexec


###########################################################
### DONE
###########################################################
log "Strong NSA-style hardening completed."
echo ""
echo "Use './secure.sh off' to temporarily disable hardening."
echo ""
