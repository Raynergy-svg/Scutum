#!/bin/zsh
set -euo pipefail

# Configures passwordless sudo for ONLY these exact commands:
#   /sbin/shutdown -r now
#   /sbin/shutdown -h now
# This lets Sentinel run `reboot` / `shutdown` unattended without granting broad sudo.

user="${SUDO_USER:-$USER}"
file="/etc/sudoers.d/irondome-sentinel"

cat <<'EOF'
This will create a sudoers drop-in allowing passwordless reboot/shutdown
for your user *only* (restricted to /sbin/shutdown -r now and -h now).

It will prompt for your password once to write /etc/sudoers.d/irondome-sentinel.
EOF

echo "Target user: $user"
echo "Sudoers file: $file"
echo

rule=$(cat <<RULE
Cmnd_Alias IRONDOME_POWER = /sbin/shutdown -r now, /sbin/shutdown -h now
$user ALL=(root) NOPASSWD: IRONDOME_POWER
RULE
)

echo "---- sudoers content ----"
echo "$rule"
echo "-------------------------"
echo

echo "Writing sudoers drop-in..."
# Use tee so the file is created as root.
echo "$rule" | sudo /usr/bin/tee "$file" >/dev/null
sudo /bin/chmod 0440 "$file"
sudo /usr/sbin/chown root:wheel "$file"

echo "Validating with visudo..."
sudo /usr/sbin/visudo -cf "$file"

echo
cat <<EOF
OK.

Next steps:
- Reboot test from Messages: send 'reboot'
- Or validate policy (no reboot): sudo -n -l /sbin/shutdown -r now
EOF
