#!/bin/sh
set -u
settings=/tmp/m2settings.xml
case $1 in
  install)
    printf '<settings><proxies><proxy><id>https</id><active>true</active><protocol>https</protocol><host>%s</host><port>3128</port></proxy><proxy><id>http</id><active>true</active><protocol>http</protocol><host>%s</host><port>3128</port></proxy></proxies></settings>' "$PROXY_HOST" "$PROXY_HOST" > "$settings"
    mvn -B -q -s "$settings" -Dmaven.repo.local=/tmp/m2 dependency:go-offline ;;
  test)
    mvn -B -o -q -s "$settings" -Dmaven.repo.local=/tmp/m2 test
    status=$?
    cat target/surefire-reports/TEST-*.xml > /tmp/report/report.xml
    exit $status ;;
esac
