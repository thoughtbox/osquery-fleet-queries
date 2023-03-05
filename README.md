# osquery-fleet-queries
Some of my own OSquery/FleetDM queries that might be of use to others. They could surely benefit from being tweaked / added to. Pull requests welcome. There may be a case for just looking for _":\/\/\S+:\S+@"_ instead of process-specific regular expressions (such as curl, wget, ftp, etc.).
# processes_bad_opsec_credentials.sql
Searches the running process list for credential leaks. This will not find historic processes, and unlikely to find short-lived ones (cron/at jobs, ad-hoc things from the command line).
# shell_history_bad_opsec_credentials.sql
Searches the shell history for credential leaks. Also looks for some environment variables that may contain credentials.
# bpf_process_bad_opsec_credentials.sql
Searches the eBPF process events table for credential leaks. Depending on how "busy" the endpoint is, there is a good chance of catching short-lived and history processes. Requires eBPF support in the kernel (Linux-only) as well as _--enable_bpf_events=true_ in OSquery's flag file.
# author
Tor Houghton
# license
Released under a Simplified BSD 2-Clause license.
