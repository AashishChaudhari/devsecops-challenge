# EC2 Server Hardening Notes

## Firewall (UFW)
- Default: deny all incoming, allow all outgoing
- Allowed inbound: 22 (SSH), 5000 (app), 80 (HTTP), 443 (HTTPS)

## Fail2ban
- SSH: ban after 3 failed attempts, 24-hour ban
- Default: ban after 5 failed attempts, 1-hour ban

## SSH Hardening
- Root login disabled
- Password authentication disabled (keys only)

## Automatic Updates
- unattended-upgrades enabled for security patches

## HTTPS / SSL (Let's Encrypt)
- Domain: aashishchaudhari.duckdns.org (DuckDNS free subdomain)
- Certificate issued via: certbot --manual --preferred-challenges dns
- Certificate location: /etc/letsencrypt/live/aashishchaudhari.duckdns.org/
- Expires: 2026-10-13 (manual renewal required before expiry)
- Nginx configured to redirect HTTP → HTTPS automatically
- Port 443 open in both UFW and AWS security group

## Renewal command (run before 2026-10-13)
Update DuckDNS TXT record then:
sudo certbot certonly --manual --preferred-challenges dns -d aashishchaudhari.duckdns.org
sudo systemctl reload nginx
