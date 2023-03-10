-- bpf_process_bad_opsec_credentials
-- looks for process events containing credentials, often exploited for lateral movement
-- (c) 2023 tor houghton // th(at)bogus.net
-- released under the simplified 2-clause bsd licence
-- this is a linux query and requires ebpf support in the kernel, and
-- /etc/osquery/osquery.flags with "--enable_bpf_events=true" configured.
SELECT uid,cwd,datetime(time,"unixepoch"),cmdline,syscall,exit_code FROM bpf_process_events 
WHERE 
regex_match(cmdline,"sshpass.*\s+-p\s+\S+",0) NOT NULL OR
-- curl has the possibility to leak so much data, this is not an exhaustive list
regex_match(cmdline,"curl\s+.*-u\s+\S+:\S+",0) NOT NULL OR
regex_match(cmdline,"curl\s+.*-d\s+\S+",0) NOT NULL OR
regex_match(cmdline,"curl\s+.*--data-raw\s+\S+",0) NOT NULL OR
regex_match(cmdline,"curl\s+.*https?:\/\/\S+:\S+@",0) NOT NULL OR
regex_match(lower(cmdline),"curl\s+.*authorization:\s+bearer\s+\S+",0) NOT NULL OR
-- wget is kind of the same
regex_match(cmdline,"wget\s+.*--(|http-|ftp-|proxy-)password=\S+",0) NOT NULL OR
regex_match(cmdline,"wget\s+.*https?://\S+:\S+@",0) NOT NULL OR
regex_match(cmdline,"wget\s+.*authorization:\s+bearer\s+\S+",0) NOT NULL OR
regex_match(cmdline,"lftp\s+.*-u\s+\S+,\S+",0) NOT NULL OR
regex_match(cmdline,"ncftp.*-p\s+\S+",0) NOT NULL OR
regex_match(cmdline,"s3cmd.*--(access|secret)_key=\S+",0) NOT NULL OR
regex_match(cmdline,"git\s+.*https?:\/\/\S+:\S+@",0) NOT NULL OR
regex_match(cmdline,"fossil\s+.*https?:\/\/\S+:\S+@",0) NOT NULL OR
regex_match(cmdline,"svn\s+.*--password\s+\S+",0) NOT NULL OR
regex_match(cmdline,"docker\s+login.*(--password|-p)\s+\S+",0) NOT NULL OR
regex_match(cmdline,"htpasswd\s+-cb\s+\S+\s+\S+\s+\S+",0) NOT NULL OR
regex_match(cmdline,"java\s+-jar\s+jenkins-cli\.jar\s+.*-auth",0) NOT NULL OR
regex_match(cmdline,"mosquitto_pub\s+.*-P\s+\S+",0) NOT NULL OR
regex_match(cmdline,"mosquitto_pub\s+.*mqtts?://\S+:\S+@",0) NOT NULL OR
regex_match(cmdline,"rabbitmqctl\s+(add_user|authenticate_user|change_password)\s+\S+\s+\S+",0) NOT NULL OR
regex_match(cmdline,"rabbitmqctl\s+.*amqp:\/\/\S+:\S+@",0) NOT NULL OR
regex_match(cmdline,"rabbitmqadmin\s+.*-p\s+\S+",0) NOT NULL OR
regex_match(cmdline,"couchbase-cli\s+.*-p\s+\S+",0) NOT NULL OR
regex_match(cmdline,"curator\s+.*--(password|http_auth)",0) NOT NULL OR
regex_match(cmdline,"zip\s+.*-P\s+\S+",0) NOT NULL OR
regex_match(cmdline,"rar\s+.*-hp\S+",0) NOT NULL OR
regex_match(cmdline,"7z\s+.*-p\S+",0) NOT NULL OR
regex_match(cmdline,"xfreerdp\s+.*\/p:\S+",0) NOT NULL OR
regex_match(cmdline,"rdesktop\s+.*-p\s+\S+",0) NOT NULL OR
regex_match(cmdline,"bcp\s+.*-P\S+",0) NOT NULL OR
regex_match(cmdline,"isql\s+.*-P\s+\S+",0) NOT NULL OR
regex_match(cmdline,"dbping\s+.*-c\s+.*PWD=\S+",0) NOT NULL OR
regex_match(cmdline,"mongo\s+.*-p\S+",0) NOT NULL OR
regex_match(cmdline,"redis-cli\s+.*-a\s+\S+",0) NOT NULL OR
regex_match(cmdline,"ldapsearch\s+.*-w\s+\S+",0) NOT NULL OR
regex_match(cmdline,"sqlplus\s+.*\S+\/\S+@\/\/",0) NOT NULL OR
regex_match(cmdline,"psql\s+.*postgresql:\/\/\S+:\S+@",0) NOT NULL OR
regex_match(cmdline,"psql\s+.*postgresql:\/\/.*&password=",0) NOT NULL OR
regex_match(cmdline,"psql\s+\[.*\s+password=.*\]",0) NOT NULL OR
regex_match(cmdline,"odbcinst\s+.*-P\s+\S+",0) NOT NULL OR
regex_match(cmdline,"winexe\s+.*-U\s+\S+:\S+",0) NOT NULL OR
regex_match(cmdline,"smbclient\s+.*(-U|--user)\s+\S+:\S+",0) NOT NULL OR
regex_match(cmdline,"smbclient\s+.*--(password|pw-nt-hash)\s+\S+",0) NOT NULL OR
regex_match(cmdline,"samba-tool\s+.*(-U|--user)\s+\S+:\S+",0) NOT NULL OR
regex_match(cmdline,"samba-tool\s+.*--(password|pw-nt-hash)\s+\S+",0) NOT NULL OR
regex_match(cmdline,"mssql-cli\s+.*-P\s+\S+",0) NOT NULL OR
regex_match(cmdline,"mysql.*\s+-p\S+",0) NOT NULL 
ORDER BY datetime(time,"unixepoch") DESC;
