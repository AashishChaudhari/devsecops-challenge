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
