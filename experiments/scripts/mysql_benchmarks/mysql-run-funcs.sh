#!/bin/bash
#
# mysql-run-funcs.sh
# Contains functions for setting up and running sysbench on MySQL.
# This script is intended to be sourced, not run directly.
#

# This variable is set by the sourcing script *after* cd'ing
current_run_pwd=$(pwd)

# --- NEW: Creates the config file. Fast. ---
function setup_mysql_config() {
  local -r mysql_dir="$1"
  cat <<EOF > install.dir/my.cnf
[client]
local-infile = 1
loose-local-infile = 1
socket=${current_run_pwd}/mysqltest.sock
mysqlx_socket=${current_run_pwd}/mysqlxtest.sock

[server]
local-infile = 1

[mysqld]
local-infile = 1
secure_file_priv = ''
socket=${current_run_pwd}/mysqltest.sock
mysqlx_socket=${current_run_pwd}/mysqlxtest.sock
skip-networking

EOF
}

# --- RENAMED: This is the slow, one-time DB initialization ---
function setup_mysql_database() {
  local -r mysql_dir="$1"
  rm -rf "${mysql_dir}"
  mkdir -p "${mysql_dir}/data"
  echo "Setup in directory: ${mysql_dir} ... "
  
  # Ensure config exists before initializing
  setup_mysql_config "${mysql_dir}"

  rm -fr "install.dir/data"
  "install.dir/bin/mysqld" \
      --defaults-file=install.dir/my.cnf --datadir=${current_run_pwd}/${mysql_dir}/data --initialize-insecure --user=${USER}
  if [[ "$?" -ne 0 ]]; then echo "*** setup_mysql_database failed ***" ; return 1; fi
  return 0
}

function start_mysqld() {
  if kill "$(pgrep mysqld)" 1>/dev/null 2>&1 ; then
    echo "Waiting for previous mysqld to stop..."
    sleep 5 # wait 5 seconds for the previous server to stop
    if kill -0 "$(pgrep mysqld)" 1>/dev/null 2>&1 ; then
        echo "Previous mysqld still running. Aborting."
        exit 1
    fi
  fi
  local -r mysql_dir="$1"
  
  # --- NEW: Ensure config exists before starting ---
  setup_mysql_config "${mysql_dir}"
  
  echo "Starting mysqld in ${mysql_dir} ..."
  "install.dir/bin/mysqld_safe" \
      --defaults-file=install.dir/my.cnf --mysqld=mysqld --datadir=${current_run_pwd}/${mysql_dir}/data --skip-mysqlx --pid-file=${current_run_pwd}/${mysql_dir}/mysqld.pid --user=$USER &
  echo "Sleeping 8 seconds to wait for server up ..."
  sleep 8
}

function kill_prog_listening() {
  if [[ "$#" -ne "2" ]]; then echo "wrong number of arguments"; return 1; fi
  local -r prog="$1"
  local -r port="$2"
  local -r pid="$(netstat -lnp 2>/dev/null | sed -nEe "s/^tcp.*\s+:::${port}\s+.*LISTEN\s+([0-9]+)\/.+\$/\1/p")"
  if [[ $pid =~ ^[0-9]+$ ]]; then
    echo "Killing $prog (pid: $pid)"
    kill $pid
    return $?
  fi
}

function stop_mysqld() {
  local -r mysql_dir="$1"
  if [ -f "${current_run_pwd}/${mysql_dir}/mysqld.pid" ]; then
    kill `cat ${current_run_pwd}/${mysql_dir}/mysqld.pid`
    sleep 3
  else
    echo "PID file not found. Sending kill to pgrep."
    pkill mysqld
    sleep 3
  fi
}

function load_dbt2_data_and_procedure() {
  set -xe
 [[ "$#" -eq 2 ]]
  local -r dbt2_source="$1"
  local -r mysql_dir="$2"
  local -r ddir="$(dirname "$dbt2_source")"
  ${dbt2_source}/scripts/mysql/mysql_load_db.sh \
    --path "${ddir}/dbt2-tool/data" \
    --local \
    --mysql-path "install.dir/bin/mysql --local-infile=1 --mysqlx_socket=/tmp/mysqlxtest.sock --mysqlx-port=53317" \
    --host "127.0.0.1" \
    --user "root"

  ${dbt2_source}/scripts/mysql/mysql_load_sp.sh \
    --client-path "install.dir/bin" \
    --sp-path ${dbt2_source}/storedproc/mysql \
    --host "127.0.0.1" \
    --user "root"
}

# for sysbench
# This function is DEPRECATED, setup_db mode is now used.
# We keep it here just in case, but it's not called by run-benchmark.sh
function setup_sysbench() {
  local -r mysql_dir="$1"
  echo "DEPRECATED: setup_sysbench called. Use 'setup_db' mode."
  setup_mysql_database "${mysql_dir}"
}

function run_sysbench_test() {
  local -r mysql_dir="$1"
  shift
  local -r test="$1"
  local -r iterations="$2"
  local -r table_size="$3"
  local -r event_number="$4"
  local -r additional_args="$5"
  local -r perfcounters="$6"
  local -r run_dir="bench.dir/${mysql_dir}"
  mkdir -p "$run_dir"
  sysbench "${test}" --table-size=${table_size} --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root prepare
  {
    if [[ "${table_size}" -ge "1000000" ]]; then
      sysbench "${test}" --table-size=${table_size} --tables=1 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
        --mysql-db=sysbench --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root prewarm
    fi
  }
  echo Running test: "${test}" ${iterations}x

  if [[ -n "$perfcounters" ]]; then
    echo "Invalid arguments."
    return 1
  fi

  if [[ "perfcounters" == "${perfcounters}" ]]; then
    return 1
    # $(PERF_COMMAND) --pid "`pgrep -x $<`" --repeat 5 -- \
    #   sysbench "${test}" --table-size=${table_size} --tables=1 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    #     --events=${event_number} --time=0 --rate=0 ${additional_args} \
    #     --mysql-db=sysbench --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root run
  else
    for i in $(seq 1 $iterations); do
      sysbench "${test}" --table-size=${table_size} --tables=1 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
        --events=${event_number} --time=0 --rate=0 ${additional_args} \
        --mysql-db=sysbench --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root run >& "${run_dir}"/"${test}".$i.log
    done
  fi

  sysbench "${test}" --table-size=${table_size} --tables=1 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    --mysql-db=sysbench --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root cleanup
}

function run_sysbench_loadtest() {
  local -r mysql_dir="$1"

  install.dir/bin/mysql -u root --socket=${current_run_pwd}/mysqltest.sock -e "DROP DATABASE IF EXISTS sysbench; CREATE DATABASE sysbench;"
  echo "Running sysbench load test..."
  run_sysbench_test "$mysql_dir" oltp_read_write 8 5000 500
  run_sysbench_test "$mysql_dir" oltp_update_index 8 5000 500
  run_sysbench_test "$mysql_dir" oltp_delete 8 5000 500
  run_sysbench_test "$mysql_dir" select_random_ranges 8 5000 500
  run_sysbench_test "$mysql_dir" oltp_read_only 8 5000 500

}

function run_sysbench_benchmark() {
  set -e
  local -r mysql_dir="$1"
  shift
  local -r iterations="$1"

  install.dir/bin/mysql -u root --socket=${current_run_pwd}/mysqltest.sock -e "DROP DATABASE IF EXISTS sysbench; CREATE DATABASE sysbench;"
  run_sysbench_test "$mysql_dir" oltp_read_write "$iterations" 10000 2500 "--range_selects=off --skip_trx"
  run_sysbench_test "$mysql_dir" oltp_update_index "$iterations" 10000 2500 "--range_selects=off --skip_trx"
  run_sysbench_test "$mysql_dir" oltp_delete "$iterations" 10000 2500 "--range_selects=off --skip_trx"
  run_sysbench_test "$mysql_dir" select_random_ranges "$iterations" 10000 2500 "--range_selects=off --skip_trx"
  run_sysbench_test "$mysql_dir" oltp_read_only "$iterations" 500000 30000 "--range_selects=off --skip_trx"

  local -a benchmarks=( select_random_ranges oltp_delete oltp_read_only oltp_read_write oltp_update_index )
  local -r log_dir="bench.dir/${mysql_dir}"
  for bn in "${benchmarks[@]}"; do
    rm -f "sysbench.${bn}.transPerSec"
    rm -f "sysbench.${bn}.time"
    for i in $(seq 1 "$iterations") ; do
      sed -nEe 's!^\s+transactions:\s+.*\((.*) per sec\.\)$!\1!p' "${log_dir}"/"${bn}"."${i}".log >> "sysbench.${bn}.transPerSec"
      sed -nEe 's!^\s+total time:\s+(.*)s$!\1!p' "${log_dir}"/"${bn}"."${i}".log >> "sysbench.${bn}.time"
    done
  done
}

function run_perf() {
  # Changed from /path/to/perf to just perf
  perf record -e cycles:u -j any "$@"
}

function perf_stat() {
  # Changed from /path/to/perf to just perf
  perf stat -r5 -e instructions,cycles,L1-icache-misses,iTLB-loads,iG-load-misses "$@"
}