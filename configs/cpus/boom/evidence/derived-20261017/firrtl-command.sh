cd /root/fanzehui/system-20261016/chipyard-release-deps/sims/verilator
export JAVA_TOOL_OPTIONS='-Xmx12G -Xss8M -Djava.io.tmpdir=/root/fanzehui/system-20261016/tmp -Dsbt.global.base=/root/fanzehui/system-20261016/cache/boom-sbt/global -Dsbt.boot.directory=/root/fanzehui/system-20261016/cache/boom-sbt/boot -Dsbt.ivy.home=/root/fanzehui/system-20261016/cache/boom-sbt/ivy2'
export COURSIER_CACHE=/root/fanzehui/system-20261016/cache/boom-sbt/coursier
flock /root/fanzehui/system-20261016/project/.superpowers/heavy-worker.lock timeout 900 make firrtl CONFIG=SmallBoomConfig RISCV=/root/fanzehui/system-20261016/tools SBT_BIN='java -jar /root/fanzehui/system-20261016/tools/sbt-launch-1.10.0.jar' -j1 > /root/fanzehui/system-20261016/evidence/chipyard-release-compat-firrtl.log 2>&1
result=$?
echo "$result" > /root/fanzehui/system-20261016/evidence/chipyard-release-compat-firrtl.exit
exit "$result"
