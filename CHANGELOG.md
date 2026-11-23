Version 3.00
-----------

el_configurator

Breaking changes:
- `NPF_VARNAME=VALUE` kernel arguments have been renamed to `ELCONF_VARNAME=VALUE`
- el script status moved away from MOTD into separate file `/var/el_configurator/state`
- New default policy for public interface is DROP, including ping

Main new features:
- Script now accepts a profile file that will be copied to `/etc/el_configurator/NAME.profile`
- Added unit testing

For all other changes, please read the git changelog.