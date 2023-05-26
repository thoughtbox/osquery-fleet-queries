-- crontab_bad_opsec_credentials
-- looks for process events containing credentials, often exploited for lateral movement
-- v0.1 (c) 2023 tor houghton // th(at)bogus.net
-- released under the simplified 2-clause bsd licence
SELECT command,path FROM crontab 
WHERE 
-- general user:secret@host match; should perhaps be protocol specific, such as
-- \s+(acap|amqp|cvs|dict|fish|ftp|h323|http|iax|imap|ldap|mqtt|mumble|pop|postgresql|sftp|sip|smb|snmp|svn|telnet|xmpp)s?
regex_match(command,"\s+\S+:\/\/\S+:\S+@\S+",0) NOT NULL OR
-- curl has the possibility to leak so much data, this is not an exhaustive list
regex_match(command,"curl\s+.*-u\s+\S+:\S+",0) NOT NULL OR
regex_match(command,"curl\s+.*-d\s+\S+",0) NOT NULL OR
regex_match(command,"curl\s+.*--data-raw\s+\S+",0) NOT NULL OR
regex_match(lower(command),"curl\s+.*authorization:\s+bearer\s+\S+",0) NOT NULL OR
-- other test; ymmv
regex_match(command,"sshpass.*\s+-p\s+\S+",0) NOT NULL OR
regex_match(command,"lftp\s+.*-u\s+\S+,\S+",0) NOT NULL OR
regex_match(command,"ncftp.*-p\s+\S+",0) NOT NULL OR
regex_match(command,"s3cmd.*--(access|secret)_key=\S+",0) NOT NULL OR
regex_match(command,"svn\s+.*--password\s+\S+",0) NOT NULL OR
regex_match(command,"docker\s+login.*(--password|-p)\s+\S+",0) NOT NULL OR
regex_match(command,"htpasswd\s+-cb\s+\S+\s+\S+\s+\S+",0) NOT NULL OR
regex_match(command,"java\s+-jar\s+jenkins-cli\.jar\s+.*-auth",0) NOT NULL OR
regex_match(command,"mosquitto_pub\s+.*-P\s+\S+",0) NOT NULL OR
regex_match(command,"rabbitmqctl\s+(add_user|authenticate_user|change_password)\s+\S+\s+\S+",0) NOT NULL OR
regex_match(command,"rabbitmqadmin\s+.*-p\s+\S+",0) NOT NULL OR
regex_match(command,"couchbase-cli\s+.*-p\s+\S+",0) NOT NULL OR
regex_match(command,"curator\s+.*--(password|http_auth)",0) NOT NULL OR
regex_match(command,"zip\s+.*-P\s+\S+",0) NOT NULL OR
regex_match(command,"rar\s+.*-hp\S+",0) NOT NULL OR
regex_match(command,"7z\s+.*-p\S+",0) NOT NULL OR
regex_match(command,"xfreerdp\s+.*\/p:\S+",0) NOT NULL OR
regex_match(command,"rdesktop\s+.*-p\s+\S+",0) NOT NULL OR
regex_match(command,"bcp\s+.*-P\S+",0) NOT NULL OR
regex_match(command,"isql\s+.*-P\s+\S+",0) NOT NULL OR
regex_match(command,"mongo\s+.*-p\S+",0) NOT NULL OR
regex_match(command,"redis-cli\s+.*-a\s+\S+",0) NOT NULL OR
regex_match(command,"ldapsearch\s+.*-w\s+\S+",0) NOT NULL OR
regex_match(command,"sqlplus\s+.*\S+\/\S+@\/\/",0) NOT NULL OR
regex_match(command,"psql\s+\[.*\s+password=.*\]",0) NOT NULL OR
regex_match(command,"odbcinst\s+.*-P\s+\S+",0) NOT NULL OR
regex_match(command,"winexe\s+.*-U\s+\S+:\S+",0) NOT NULL OR
regex_match(command,"smbclient\s+.*(-U|--user)\s+\S+:\S+",0) NOT NULL OR
regex_match(command,"smbclient\s+.*--password\s+\S+",0) NOT NULL OR
regex_match(command,"samba-tool\s+.*(-U|--user)\s+\S+:\S+",0) NOT NULL OR
regex_match(command,"samba-tool\s+.*--password\s+\S+",0) NOT NULL OR
regex_match(command,"mssql-cli\s+.*-P\s+\S+",0) NOT NULL OR
regex_match(command,"mysql.*\s+-p\S+",0) NOT NULL;
