-- shell_history_bad_opsec_credentials
-- looks for process events containing credentials, often exploited for lateral movement
-- querying the "shell_history" table may be unreliable if a user's terminal session is still active
-- v0.2 (c) 2023 tor houghton // th(at)bogus.net
-- released under the simplified 2-clause bsd licence
-- this query is supported by macos and linux
SELECT u.username, s.command, s.time FROM users u CROSS JOIN shell_history s USING (uid) 
WHERE 
-- generic URI match
regex_match(s.command,"\S+:\/\/\S+:\S+@",0) NOT NULL OR
-- the rest
regex_match(s.command,"(AWS_ACCESS_KEY|AWS_SECRET_ACCESS_KEY)=\S+",0) NOT NULL OR
regex_match(s.command,"AZURE_(CLIENT_SECRET|PASSWORD)=\S+",0) NOT NULL OR
regex_match(s.command,"GITHUB_TOKEN=\S+",0) NOT NULL OR
regex_match(s.command,"PGPASSWORD=\S+",0) NOT NULL OR
regex_match(s.command,"MYSQL_PWD=\S+",0) NOT NULL OR
regex_match(s.command,"RABBITMQ_DEFAULT_PASS=\S+",0) NOT NULL OR
regex_match(s.command,"SQLCONNECT=.*PWD=\S+",0) NOT NULL OR
regex_match(s.command,"CB_(REST|CLIENT_CERT|CLIENT_KEY)_PASSWORD=\S+",0) NOT NULL OR
-- very generic, but smbclient/samba-tool will check this variable
regex_match(s.command,"PASSWD=\S+",0) NOT NULL OR
regex_match(s.command,"echo\s+\S+\s*\|\s*sudo\s+-(S|-stdin)",0) NOT NULL OR
regex_match(s.command,"echo\s+\S+\s*\|\s*remmina\s+--encrypt-password",0) NOT NULL OR
-- the following are copied from bpf_process_bad_opsec_credentials
regex_match(s.command,"sshpass.*\s+-p\s+\S+",0) NOT NULL OR
-- curl has the possibility to leak so much data, this is not an exhaustive list
regex_match(s.command,"curl\s+.*-u\s+\S+:\S+",0) NOT NULL OR
regex_match(s.command,"curl\s+.*-d\s+\S+",0) NOT NULL OR
regex_match(s.command,"curl\s+.*--data-raw\s+\S+",0) NOT NULL OR
regex_match(lower(s.command),"curl\s+.*authorization:\s+bearer\s+\S+",0) NOT NULL OR
-- wget is kind of the same
regex_match(s.command,"wget\s+.*--(|http-|ftp-|proxy-)password=\S+",0) NOT NULL OR
regex_match(lower(s.command),"wget\s+.*authorization:\s+bearer\s+\S+",0) NOT NULL OR
regex_match(s.command,"lftp\s+.*-u\s+\S+,\S+",0) NOT NULL OR
regex_match(s.command,"ncftp.*-p\s+\S+",0) NOT NULL OR
regex_match(s.command,"s3cmd.*--(access|secret)_key=\S+",0) NOT NULL OR
regex_match(s.command,"svn\s+.*--password\s+\S+",0) NOT NULL OR
regex_match(s.command,"docker\s+login.*(--password|-p)\s+\S+",0) NOT NULL OR
regex_match(s.command,"htpasswd\s+-cb\s+\S+\s+\S+\s+\S+",0) NOT NULL OR
regex_match(s.command,"java\s+-jar\s+jenkins-cli\.jar\s+.*-auth",0) NOT NULL OR
regex_match(s.command,"mosquitto_pub\s+.*-P\s+\S+",0) NOT NULL OR
regex_match(s.command,"rabbitmqctl\s+(add_user|authenticate_user|change_password)\s+\S+\s+\S+",0) NOT NULL OR
regex_match(s.command,"rabbitmqadmin\s+.*-p\s+\S+",0) NOT NULL OR
regex_match(s.command,"couchbase-cli\s+.*-p\s+\S+",0) NOT NULL OR
regex_match(s.command,"curator\s+.*--(password|http_auth)",0) NOT NULL OR
regex_match(s.command,"zip\s+.*-P\s+\S+",0) NOT NULL OR
regex_match(s.command,"rar\s+.*-hp\S+",0) NOT NULL OR
regex_match(s.command,"7z\s+.*-p\S+",0) NOT NULL OR
regex_match(s.command,"xfreerdp\s+.*\/p:\S+",0) NOT NULL OR
regex_match(s.command,"rdesktop\s+.*-p\s+\S+",0) NOT NULL OR
regex_match(s.command,"bcp\s+.*-P\S+",0) NOT NULL OR
regex_match(s.command,"isql\s+.*-P\s+\S+",0) NOT NULL OR
regex_match(s.command,"dbping\s+.*-c\s+.*PWD=\S+",0) NOT NULL OR
regex_match(s.command,"mongo\s+.*-p\S+",0) NOT NULL OR
regex_match(s.command,"redis-cli\s+.*-a\s+\S+",0) NOT NULL OR
regex_match(s.command,"ldapsearch\s+.*-w\s+\S+",0) NOT NULL OR
regex_match(s.command,"sqlplus\s+.*\S+\/\S+@\/\/",0) NOT NULL OR
regex_match(s.command,"psql\s+.*postgresql:\/\/.*&password=",0) NOT NULL OR
regex_match(s.command,"psql\s+\[.*\s+password=.*\]",0) NOT NULL OR
regex_match(s.command,"odbcinst\s+.*-P\s+\S+",0) NOT NULL OR
regex_match(s.command,"winexe\s+.*-U\s+\S+:\S+",0) NOT NULL OR
regex_match(s.command,"smbclient\s+.*(-U|--user)\s+\S+:\S+",0) NOT NULL OR
regex_match(s.command,"smbclient\s+.*--(password|pw-nt-hash)\s+\S+",0) NOT NULL OR
regex_match(s.command,"samba-tool\s+.*(-U|--user)\s+\S+:\S+",0) NOT NULL OR
regex_match(s.command,"samba-tool\s+.*--(password|pw-nt-hash)\s+\S+",0) NOT NULL OR
regex_match(s.command,"mssql-cli\s+.*-P\s+\S+",0) NOT NULL OR
regex_match(s.command,"mysql.*\s+-p\S+",0) NOT NULL 
ORDER BY datetime(s.time,"unixepoch") DESC;
