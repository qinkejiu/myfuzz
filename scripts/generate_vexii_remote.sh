#!/usr/bin/env bash
# Generate the pinned cacheless RV32 VexiiRiscv in an isolated remote workspace.
set -euo pipefail

: "${MYFUZZ_VEXII_WORK_ROOT:?set MYFUZZ_VEXII_WORK_ROOT to the isolated workspace}"
vexii_work_root=$(realpath "${MYFUZZ_VEXII_WORK_ROOT}")
vexii_source_root="$vexii_work_root/project/third_party/vexiiriscv_upstream_reference"
vexii_jdk="$vexii_work_root/tools/jdk-21.0.12.1+1"
vexii_launcher="$vexii_work_root/tools/sbt-launch-1.10.0.jar"
vexii_cache="$vexii_work_root/cache"
vexii_user_home="$vexii_work_root/home"
vexii_tmp="$vexii_work_root/tmp"
vexii_logs="$vexii_work_root/evidence"

case "$vexii_work_root" in
  /root/fanzehui/*) ;;
  *) echo 'Vexii workspace must be inside /root/fanzehui' >&2; exit 2 ;;
esac
test -f "$vexii_source_root/build.sbt"
test -x "$vexii_jdk/bin/java"
test -f "$vexii_launcher"
test -f "$vexii_source_root/ext/SpinalHDL/build.sbt"
test -d "$vexii_source_root/ext/rvls/bindings/spinal"
test "$(sha256sum "$vexii_jdk/bin/java" | cut -d' ' -f1)" = 2a207f5e7d075afa01d97f8048389a64432a44c4a5af0f5e77d6e286ec5f401d
test "$(sha256sum "$vexii_jdk/lib/modules" | cut -d' ' -f1)" = 70c5465dabf8e1bec2860631ea3ffd342f0ec23a5e2efd3a389d2abe32448f98
test "$(sha256sum "$vexii_launcher" | cut -d' ' -f1)" = a3f85f3684d2d457dab46e7e3fe7622a65065f0f104c0e4269c01df32147f670
mkdir -p "$vexii_cache/sbt-global" "$vexii_cache/sbt-boot" \
  "$vexii_cache/ivy2" "$vexii_cache/coursier" "$vexii_cache/coursier-jvm" \
  "$vexii_user_home/config" "$vexii_user_home/data" "$vexii_user_home/java-prefs" \
  "$vexii_user_home/java-system-prefs" "$vexii_tmp" "$vexii_logs"

export JAVA_HOME="$vexii_jdk"
export PATH="$vexii_jdk/bin:$PATH"
export TMPDIR="$vexii_tmp"
export XDG_CACHE_HOME="$vexii_cache"
export XDG_CONFIG_HOME="$vexii_user_home/config"
export XDG_DATA_HOME="$vexii_user_home/data"
export COURSIER_CACHE="$vexii_cache/coursier"
export COURSIER_JVM_CACHE="$vexii_cache/coursier-jvm"
export SPINALHDL_FROM_SOURCE=1
export SPINALHDL_PATH="$vexii_source_root/ext/SpinalHDL"
export JAVA_TOOL_OPTIONS="-Duser.home=$vexii_user_home -Djava.io.tmpdir=$vexii_tmp -Dsbt.global.base=$vexii_cache/sbt-global -Dsbt.boot.directory=$vexii_cache/sbt-boot -Dsbt.ivy.home=$vexii_cache/ivy2 -Divy.home=$vexii_cache/ivy2 -Dsbt.coursier.home=$vexii_cache/coursier -Dcoursier.cache=$vexii_cache/coursier -Djna.tmpdir=$vexii_tmp -Djava.util.prefs.userRoot=$vexii_user_home/java-prefs -Djava.util.prefs.systemRoot=$vexii_user_home/java-system-prefs -XX:ErrorFile=$vexii_logs/hs_err_pid%p.log -XX:HeapDumpPath=$vexii_logs -Xss16M -Xmx8G"

cd "$vexii_source_root"
test "$(git rev-parse HEAD)" = 0dc189e1335d7ad0739c3298de09fcb3d2b956d4
test "$(git -C ext/SpinalHDL rev-parse HEAD)" = 58837d37f92bea3a43dc7b0b6dee38038c85db6d
test "$(git -C ext/rvls rev-parse HEAD)" = 847ce99fd2b28a5c0ccb1ec2683311cf97a9fefc

"$vexii_jdk/bin/java" -version 2> "$vexii_logs/vexii-java-version.log"
sha256sum "$vexii_launcher" > "$vexii_logs/vexii-sbt-launch.sha256"
printf '%s\n' \
  'runMain vexiiriscv.Generate --xlen 32 --fetch-axi4 --lsu-axi4 --reset-vector 2147483648 --region base=80000000,size=00100000,main=1,exe=1 --region base=40000000,size=00001000,main=0,exe=0' \
  > "$vexii_logs/vexii-generate-command.txt"
flock -n "$vexii_work_root/project/.superpowers/heavy-worker.lock" \
  timeout 3600 "$vexii_jdk/bin/java" -jar "$vexii_launcher" \
  'runMain vexiiriscv.Generate --xlen 32 --fetch-axi4 --lsu-axi4 --reset-vector 2147483648 --region base=80000000,size=00100000,main=1,exe=1 --region base=40000000,size=00001000,main=0,exe=0' \
  > "$vexii_logs/vexii-generate.log" 2>&1
sha256sum VexiiRiscv.v > "$vexii_logs/vexii-generated-rtl.sha256"
