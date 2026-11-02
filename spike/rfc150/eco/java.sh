#!/bin/sh
set -u
settings=/tmp/m2settings.xml
case $1 in
  install)
    printf '<settings><proxies><proxy><id>https</id><active>true</active><protocol>https</protocol><host>%s</host><port>3128</port></proxy><proxy><id>http</id><active>true</active><protocol>http</protocol><host>%s</host><port>3128</port></proxy></proxies></settings>' "$PROXY_HOST" "$PROXY_HOST" > "$settings"
    mvn -B -q -s "$settings" -Dmaven.repo.local=/tmp/m2 -Duser.home=/tmp/home dependency:go-offline &&
      mvn -B -q -s "$settings" -Dmaven.repo.local=/tmp/m2 -Duser.home=/tmp/home test -Dmaven.test.failure.ignore=true ;;
  test)
    rm -rf target/surefire-reports
    mvn -B -o -q -s "$settings" -Dmaven.repo.local=/tmp/m2 -Duser.home=/tmp/home test
    status=$?
    cat target/surefire-reports/TEST-*.xml > /tmp/report/report.xml
    exit $status ;;
esac
