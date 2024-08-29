# libnss_mtl

NSS plugin to map all unknown users to selected local one. MTL stands for map-to-local.
It can be used together with custom PAM modules that authenticate users using external resources (e.g. RADIUS or TACACS+ servers).

Currently it implements routines for passwd, shadow and group NSS databases.
All non-local users are mapped to single "target user" defined in configuration.
What it means is that while the username itself is preserved, uid, gid, default shell as well as supplementary group membership
are inherited from aforementioned skeleton user.

Due to that, please carefully review target user permissions and capabilities before using it in production.

Password hash is set to a static always-invalid value, since the assumption is that user authentication
is done via custom PAM modules.

## Configuration

This plugin reads its configuration from /etc/nss_mtl.conf file.
Example configuration is included in the repository.