# Editing an existing UNUNKNOWNTUN tunnel

Use `sudo ununknowntunctl list`, then `sudo ununknowntunctl edit TUNNEL_ID`. The installer
also offers Manage tunnels → Edit all tunnel settings. `sudo ununknowntunctl edit-show
TUNNEL_ID` displays configuration without applying an edit. Upgrade both peers
to a compatible version before using new paired features.

The editor supports display name, endpoint IP/port, domain, existing certificate
and key paths, token, WSS/XHTTP paths and transport, MUX, TLS/ECH/fragmentation,
resource/session settings, CDN provider and Iran entry migrations. Service and
customer identities remain stable. Invalid inputs are corrected one field at a
time. Review the proposed change before applying it.

## Paired changes

Domain, token, path and transport changes can require the signed edit code on the
other peer. Use `sudo ununknowntunctl edit-apply TUNNEL_ID`; `apply-update` is an alias.
Edit codes are separate from initial install codes. Old or mismatched codes are
rejected; regenerate them after upgrading both sides. Sync codes do not export
TLS private keys or modify a remote Xray panel.

Prepare the replacement DNS/CDN name and a valid matching certificate first.
The editor accepts existing absolute certificate/key paths; it does not issue
or renew a certificate for a newly entered domain. Keep the existing renewal
arrangement. The origin's local CA and the public CDN connection's trust are
separate settings. Changing a domain cannot repair a broken route by itself.

## Iran entry migration

The migration wizard explicitly converts direct entry to proxy or standalone
Nginx HTTPS entry, and WS/XHTTP client entry. It preserves customer identities,
usage and quotas, allocates/checks ports and rebuilds client exports. Each CDN
provider has protocol and port constraints; the editor validates them.

Configure the matching Xray inbound and DNS/CDN account separately. Proxied
entry terminates public TLS at Nginx and forwards to the corresponding private
inbound. Direct entry passes the client's own protocol through. Changing the
interserver transport does not automatically change the client inbound.
Previously distributed client configurations do not update themselves.

Only the selected managed site is edited. Existing certificates and unrelated
services are preserved. Returning to direct entry requires a distinct checked
public port for every customer. Old site settings remain in the scoped backup.

## Applying and recovering

Configuration validation precedes restart/reload. Scoped backups and rollback
protect managed files; traffic accounting is not rolled back to an older value.
A paired change may interrupt traffic until the other side is updated. Existing
TCP connections are not guaranteed to survive a restart. Test a real client
connection after applying the new settings.

ECH remains strict: the TLS endpoint must accept it. Nginx created by this
installer does not automatically gain ECH keys. ClientHello fragmentation and
ECH are separate choices. Dial endpoint, TLS SNI and HTTP Host are independent
fields; changing one does not automatically replace the others.

For Direct ICMP L3, use its endpoint manager and matched pair generator described
in [DIRECT-ICMP.md](DIRECT-ICMP.md), rather than the WSS/XHTTP editor.
