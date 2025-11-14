#!/bin/bash
#
# mysql-run-funcs.sh
# Bash function library for running MySQL and sysbench.
# This script is intended to be sourced, not run directly.
#

# This variable is set by the sourcing script *after* cd'ing
current_run_pwd=$(pwd)

# === SERVER FUNCTIONS ===

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
# --- FIX: Removed deprecated plugin for MySQL 8.4 ---
local-infile = 1
secure_file_priv = ''
socket=${current_run_pwd}/mysqltest.sock
mysqlx_socket=${current_run_pwd}/mysqlxtest.sock
skip-networking

EOF
}

# --- This is the slow, one-time DB initialization ---
function setup_db() {
  local -r mysql_dir="$1"
  rm -rf "${mysql_dir}"
  mkdir -p "${mysql_dir}/data"
  echo "Setup in directory: ${mysql_dir} ... "
  setup_mysql_config "${mysql_dir}"

  rm -fr "install.dir/data"
  "install.dir/bin/mysqld" \
      --defaults-file=install.dir/my.cnf --datadir=${current_run_pwd}/${mysql_dir}/data --initialize-insecure --user=${USER}
  if [[ "$?" -ne 0 ]]; then echo "*** setup failed ***" ; return 1; fi
  return 0
}

function start_server() {
  if kill "$(pgrep mysqld)" 1>/dev/null 2>&1 ; then
    echo "Waiting for previous mysqld to stop..."
    sleep 5
    if kill -0 "$(pgrep mysqld)" 1>/dev/null 2>&1 ; then
        echo "Previous mysqld still running. Aborting."
        exit 1
    fi
  fi
  local -r mysql_dir="$1"
  setup_mysql_config "${mysql_dir}"
  echo "Starting mysqld in ${mysql_dir} ..."

  "install.dir/bin/mysqld_safe" \
      --defaults-file=install.dir/my.cnf --mysqld=mysqld --datadir=${current_run_pwd}/${mysql_dir}/data --skip-mysqlx --pid-file=${current_run_pwd}/${mysql_dir}/mysqld.pid --user=$USER > /dev/null 2>&1 &
  echo "Sleeping 8 seconds to wait for server up ..."
  sleep 8
}

function stop_server() {
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

# === SYSBENCH HELPER FUNCTIONS ===

function create_database() {
    install.dir/bin/mysql -u root --socket=${current_run_pwd}/mysqltest.sock -e "DROP DATABASE IF EXISTS sysbench; CREATE DATABASE sysbench;"
}

# --- Test 1: oltp_read_write ---
function prepare_oltp_rw() {
    sysbench "oltp_read_write" --table-size=10000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root prepare
}
function run_oltp_rw() {
    local -r iterations="$2"
    sysbench "oltp_read_write" --table-size=10000 --events=2500 --range_selects=off --skip_trx \
    --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root run
}
function cleanup_oltp_rw() {
    sysbench "oltp_read_write" --table-size=10000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root cleanup
}

# --- Test 2: oltp_update_index ---
function prepare_oltp_ui() {
    sysbench "oltp_update_index" --table-size=10000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root prepare
}
function run_oltp_ui() {
    local -r iterations="$2"
    sysbench "oltp_update_index" --table-size=10000 --events=2500 --range_selects=off --skip_trx \
    --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root run
}
function cleanup_oltp_ui() {
    sysbench "oltp_update_index" --table-size=10000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root cleanup
}

# --- Test 3: oltp_delete ---
function prepare_oltp_del() {
    sysbench "oltp_delete" --table-size=10000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root prepare
}
function run_oltp_del() {
    local -r iterations="$2"
    sysbench "oltp_delete" --table-size=10000 --events=2500 --range_selects=off --skip_trx \
    --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root run
}
function cleanup_oltp_del() {
    sysbench "oltp_delete" --table-size=10000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root cleanup
}

# --- Test 4: select_random_ranges ---
function prepare_select_rr() {
    sysbench "select_random_ranges" --table-size=10000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root prepare
}
function run_select_rr() {
    local -r iterations="$2"
    sysbench "select_random_ranges" --table-size=10000 --events=2500 --range_selects=off --skip_trx \
    --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root run
}
function cleanup_select_rr() {
    sysbench "select_random_ranges" --table-size=10000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root cleanup
}

# --- Test 5: oltp_read_only (different table) ---
function prepare_oltp_ro() {
    sysbench "oltp_read_only" --table-size=500000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root prepare
    sysbench "oltp_read_only" --table-size=500000 --tables=1 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    --mysql-db=sysbench --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root prewarm
}
function run_oltp_ro() {
    local -r iterations="$2"
    sysbench "oltp_read_only" --table-size=500000 --events=30000 --range_selects=off --skip_trx \
    --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root run
}
function cleanup_oltp_ro() {
    sysbench "oltp_read_only" --table-size=500000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
    --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root cleanup
}


# ---
# --- Full workload functions (for 'loadtest' and 'benchmark' bisection)
# ---

# This is the function that does prepare, run, and cleanup
function run_sysbench_test_full() {
  local -r mysql_dir="$1"
  shift
  local -r test="$1"
  local -r iterations="$2"
  local -r table_size="$3"
  local -r event_number="$4"
  local -r additional_args="$5"
  
  local table_name_arg=""
  local table_name="sbtest1" # default
  # --- FIX: Removed invalid --table-name flag ---
  if [ "$test" == "oltp_read_only" ]; then
    table_name_arg="" # This test does not support --table-name
    table_name="sbtest1" # It must use the default table
  fi
  
  local -r run_dir="bench.dir/${mysql_dir}"
  mkdir -p "$run_dir"
  # --- FIX: Use a consistent log file name ---
  local -r log_file="${run_dir}"/"${test}."${iterations}.log
  
  # Call the individual functions
  # Note: we use the function names directly, not "prepare_${test}"
  "prepare_${test//-/_}" "${mysql_dir}"
  
  echo "Running test: ${test} ${iterations}x"
  # This is a bug from the original script, it should just be $iterations
  for i in $(seq 1 $iterations); do
    "run_${test//-/_}" "${mysql_dir}" "1" >& "$log_file" # We run 1 iteration, as $iterations is for the loop
  done
  
  "cleanup_${test//-/_}" "${mysql_dir}"
}

# --- This function is still used by 'loadtest' mode ---
function run_sysbench_loadtest() {
  local -r mysql_dir="$1"
  create_database
  echo "Running sysbench load test..."
  # --- FIX: All tests will now run on sbtest1, with different sizes ---
  run_sysbench_test_full "$mysql_dir" oltp_read_write 8 5000 500
  run_sysbench_test_full "$mysql_dir" oltp_update_index 8 5000 500
  run_sysbench_test_full "$mysql_dir" oltp_delete 8 5000 500
  run_sysbench_test_full "$mysql_dir" select_random_ranges 8 5000 500
  run_sysbench_test_full "$mysql_dir" oltp_read_only 8 5000 500
}

# --- This function is called by 'benchmark' mode (for bisection) ---
function run_sysbench_benchmark() {
  set -e
  local -r mysql_dir="$1"
  shift
  local -r iterations="$1"

  create_database
  
  # --- FIX: All tests will now run on sbtest1, with different sizes ---
  run_sysbench_test_full "$mysql_dir" "oltp_read_write" "$iterations" 10000 2500 "--range_selects=off --skip_trx"
  run_sysbench_test_full "$mysql_dir" "oltp_update_index" "$iterations" 10000 2500 "--range_selects=off --skip_trx"
  run_sysbench_test_full "$mysql_dir" "oltp_delete" "$iterations" 10000 2500 "--range_selects=off --skip_trx"
  run_sysbench_test_full "$mysql_dir" "select_random_ranges" "$iterations" 10000 2500 "--range_selects=off --skip_trx"
  run_sysbench_test_full "$mysql_dir" "oltp_read_only" "$iterations" 500000 30000 "--range_selects=off --skip_trx"
  
  local -a benchmarks=( select_random_ranges oltp_delete oltp_read_only oltp_read_write oltp_update_index )
  local -r log_dir="bench.dir/${mysql_dir}"
  for bn in "${benchmarks[@]}"; do
    # --- FIX: All logs go to the same table name ---
    local table_name="sbtest1"
    
    rm -f "sysbench.${bn}.transPerSec"
    rm -f "sysbench.${bn}.time"
    for i in $(seq 1 "$iterations") ; do
      # Check if log file exists before trying to parse it
      if [ -f "${log_dir}"/"${bn}_${table_name}."${i}.log ]; then
        sed -nEe 's!^\s+transactions:\s+.*\((.*) per sec\.\)$!\1!p' "${log_dir}"/"${bn}_${table_name}."${i}.log >> "sysbench.${bn}.transPerSec"
        sed -nEe 's!^\s+total time:\s+(.*)s$!\1!p' "${log_dir}"/"${bn}_${table_name}."${i}.log >> "sysbench.${bn}.time"
      fi
    done
  done
}