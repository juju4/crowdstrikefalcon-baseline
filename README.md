# Crowdstrike Falcon InSpec Profile

Ensure Crowdstrike Falcon is installed, configured and active on Linux, MacOS or Windows system.

```
% inspec exec crowdstrikefalcon-baseline -t ssh://user@hostname
% inspec exec crowdstrikefalcon-baseline -t ssh://user@hostname --sudo
```

## Known issues

* inspec does not provide a per task sudo option outside of calling it for specific command, meaning only the global option can be used to fully evaluate baseline. This is required for file evaluations.

* If not using default ssh key path, you may need to specify it manually
```
% inspec exec crowdstrikefalcon-baseline -t ssh://user@hostname -i /path/to/id_rsa.custom
```

## References

* https://www.crowdstrike.com/falcon-platform/
