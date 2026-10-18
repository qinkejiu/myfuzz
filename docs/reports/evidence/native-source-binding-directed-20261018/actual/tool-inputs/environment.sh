# Isolated environment, prepared without invoking any compiler/frontend/model.
case "${MYFUZZ_SOURCE_ROOT:-}" in
 /root/fanzehui/myfuzz/operations/*/project) ;;
 *) echo 'independent operations project required' >&2; return 2 ;;
esac
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE GIT_NAMESPACE GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_CONFIG_COUNT GIT_CONFIG_PARAMETERS GIT_CONFIG_SYSTEM
unset PYTHONHOME PYTHONSTARTUP PYTHONUSERBASE PYTHONPYCACHEPREFIX PYTEST_ADDOPTS
unset VERILATOR_ROOT VERILATOR_BIN VERILATOR_TEST_FLAGS VERILATOR_GDB VERILATOR_VALGRIND
export PATH=/root/fanzehui/myfuzz/operations/environment-20261018-attempt3/bin:/root/fanzehui/myfuzz/tools/verilator-5.051/bin:/usr/bin:/bin
export TMPDIR=/root/fanzehui/myfuzz/operations/environment-20261018-attempt3/tmp
export PYTHONPATH="$MYFUZZ_SOURCE_ROOT/src:$MYFUZZ_SOURCE_ROOT:/root/fanzehui/myfuzz/pythonlib"
export PYTHONNOUSERSITE=1 PYTHONDONTWRITEBYTECODE=1 PYTHONOPTIMIZE=0 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
export GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/root/fanzehui/myfuzz/operations/environment-20261018-attempt3/empty.gitconfig GIT_OPTIONAL_LOCKS=0 GIT_NO_LAZY_FETCH=1
