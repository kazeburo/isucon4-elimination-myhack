#!/bin/sh
set -x
set -e
cd $(dirname $0)

myuser=root
mydb=isu4_qualifier
myhost=127.0.0.1
myport=3306
mysql -h ${myhost} -P ${myport} -u ${myuser} -e "DROP DATABASE IF EXISTS ${mydb}; CREATE DATABASE ${mydb}"
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/schema.sql
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/dummy_users.sql
mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb} < sql/dummy_log.sql
#cat <<'EOF' | mysql -h ${myhost} -P ${myport} -u ${myuser} ${mydb}
#alter table login_log add index ip (ip), add index user_id (user_id);
#EOF
# here is /home/isucon
(cd webapp/perl && carton exec perl init.pl)

