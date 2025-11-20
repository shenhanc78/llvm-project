#!/bin/bash
#
# mysql-run-funcs.sh
# Bash function library for running MySQL and sysbench.
# This script is intended to be sourced, not run directly.
#

# This variable is set by the sourcing script *after* cd'ing
current_run_pwd=$(pwd)

# --- Configuration ---
MYSQLD_CORE="0"

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
  
  DATA_DIR="${current_run_pwd}/${mysql_dir}/data"
  
  # --- CRITICAL FIX: Kill zombies BEFORE deleting the directory ---
  # If we don't kill mysqld here, 'rm -rf' deletes the PID file, 
  # and start_server won't know there's a zombie running.
  if pgrep -f "mysqld" > /dev/null; then
      echo "Killing lingering mysqld processes before setup..."
      pkill -9 -f "mysqld"
      sleep 2
  fi

  # 1. Clean and create the absolute path for the data directory
  rm -rf "${mysql_dir}"
  mkdir -p "${mysql_dir}/data"
  
  echo "Setup in directory: ${mysql_dir} ... "
  setup_mysql_config "${mysql_dir}"

  rm -fr "install.dir/data"
  "install.dir/bin/mysqld" \
      --defaults-file=install.dir/my.cnf --datadir="${DATA_DIR}" --initialize-insecure --user=${USER}
  if [[ "$?" -ne 0 ]]; then echo "*** setup failed ***" ; return 1; fi
  
  # Permission fix to ensure current user owns the fresh data
  chown -R ${USER}:${USER} "${DATA_DIR}" 2>/dev/null || true
  
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
  echo "Starting mysqld in ${mysql_dir} (Pinned to Core ${MYSQLD_CORE}) ..."

  DATA_DIR="${current_run_pwd}/${mysql_dir}/data" 
  PID_FILE="${DATA_DIR}/mysqld.pid"
  
  # Ensure directory exists just prior to launch
  mkdir -p "${DATA_DIR}" 2>/dev/null || true 
  # Force permissions to be writable by user (Fixes errno: 2)
  chmod 755 "${DATA_DIR}"
  rm -f "${PID_FILE}" # Ensure old PID file is gone

  # --- CRITICAL FIX: Reintroduce taskset around mysqld_safe ---
  taskset -c ${MYSQLD_CORE} "install.dir/bin/mysqld_safe" \
      --defaults-file=install.dir/my.cnf --mysqld=mysqld \
      --datadir="${DATA_DIR}" \
      --skip-mysqlx \
      --pid-file="${PID_FILE}" --user=$USER > /dev/null 2>&1 &
      
  echo "Sleeping 8 seconds to wait for server up ..."
  sleep 8
}

function stop_server() {
  local -r mysql_dir="$1"
  PID_FILE="${current_run_pwd}/${mysql_dir}/data/mysqld.pid"
  
  if [ -f "$PID_FILE" ]; then
    kill `cat $PID_FILE` 2>/dev/null || true
    sleep 3
    rm -f "$PID_FILE"
  else
    echo "PID file not found. Sending kill to pgrep."
    pkill mysqld 2>/dev/null || true
    sleep 3
  fi
}

# === SYSBENCH HELPER FUNCTIONS ===

function create_database() {
  # The permissions fix in start_server ensures MySQL can create the directory itself.
  install.dir/bin/mysql -u root --socket=${current_run_pwd}/mysqltest.sock -e "DROP DATABASE IF EXISTS sysbench; CREATE DATABASE sysbench;"
}

# --- Test 1: oltp_read_write ---
function prepare_oltp_read_write() {
  sysbench "oltp_read_write" --table-size=10000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
      --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root prepare
}
function run_oltp_read_write() {
  local -r iterations="$2"
  sysbench "oltp_read_write" --table-size=10000 --events=2500 --range-selects=off --skip_trx \
      --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
      --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root run
}
function cleanup_oltp_read_write() {
  sysbench "oltp_read_write" --table-size=10000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
      --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root cleanup
}

# --- Test 2: oltp_update_index ---
function prepare_oltp_update_index() {
  sysbench "oltp_update_index" --table-size=10000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
      --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root prepare
}
function run_oltp_update_index() {
  local -r iterations="$2"
  sysbench "oltp_update_index" --table-size=10000 --events=2500 --range-selects=off --skip_trx \
      --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
      --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root run
}
function cleanup_oltp_update_index() {
  sysbench "oltp_update_index" --table-size=10000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
      --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root cleanup
}

# --- Test 3: oltp_delete ---
function prepare_oltp_delete() {
  sysbench "oltp_delete" --table-size=10000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
      --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root prepare
}
function run_oltp_delete() {
  local -r iterations="$2"
  sysbench "oltp_delete" --table-size=10000 --events=2500 --range-selects=off --skip_trx \
      --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
      --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root run
}
function cleanup_oltp_delete() {
  sysbench "oltp_delete" --table-size=10000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
      --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root cleanup
}

# --- Test 4: select_random_ranges ---
function prepare_select_random_ranges() {
  sysbench "select_random_ranges" --table-size=10000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
      --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root prepare
}
function run_select_random_ranges() {
  local -r iterations="$2"
  sysbench "select_random_ranges" --table-size=10000 --events=2500 --range-selects=off --skip_trx \
      --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
      --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root run
}
function cleanup_select_random_ranges() {
  sysbench "select_random_ranges" --table-size=10000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
      --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root cleanup
}

# --- Test 5: oltp_read_only (Using Full Name) ---
function prepare_oltp_read_only() {
  sysbench "oltp_read_only" --table-size=500000 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
      --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root prepare
  sysbench "oltp_read_only" --table-size=500000 --tables=1 --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
      --mysql-db=sysbench --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root prewarm
}
function run_oltp_read_only() {
  local -r iterations="$2"
  sysbench "oltp_read_only" --table-size=500000 --events=30000 --range-selects=off --skip_trx \
      --num-threads=1 --rand-type=uniform --rand-seed=1 --db-driver=mysql \
      --mysql-db=sysbench --tables=1 --mysql-socket=${current_run_pwd}/mysqltest.sock --mysql-user=root run
}
function cleanup_oltp_read_only() {
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
  local -r test="$1" # e.g., "oltp_read_write"
  local -r iterations="$2"
  local -r table_size="$3"
  local -r event_number="$4"
  local -r additional_args="$5"
  
  local table_name_arg=""
  local table_name="sbtest1" # default
  
  local -r run_dir="bench.dir/${mysql_dir}"
  mkdir -p "$run_dir"
  # --- FIX: Use a consistent log file name ---
  local -r log_file="${run_dir}"/"${test}."${iterations}.log
  
  # Call the individual functions (FIX: No more string manipulation needed)
  "prepare_${test}" "${mysql_dir}"
  
  echo "Running test: ${test} ${iterations}x"
  # This is a bug from the original script, it should just be $iterations
  for i in $(seq 1 $iterations); do
    "run_${test}" "${mysql_dir}" "1" >& "$log_file" # We run 1 iteration, as $iterations is for the loop
  done
  
  "cleanup_${test}" "${mysql_dir}"
}

# --- Function to handle only setup and start ---
function setup_and_start() {
  local -r mysql_dir="$1"
  
  setup_db "$mysql_dir" # Initialize the data directory
  start_server "$mysql_dir" # Launch the mysqld process

  # Wait for MySQL to be ready
  local max_retries=10
  local retry_count=0
  while ! install.dir/bin/mysql -u root --socket=${current_run_pwd}/mysqltest.sock -e "SELECT 1" > /dev/null 2>&1 && [ $retry_count -lt $max_retries ]; do
      sleep 1
      retry_count=$((retry_count + 1))
  done

  if [ $retry_count -ge $max_retries ]; then
      echo "FATAL: MySQL server failed to start or connect within timeout."
      return 1
  fi

  create_database # Create the sysbench database
  
  echo "Setup and Server Ready."
  return 0
}

# --- NEW: Function to handle only the workload runs (the part to profile) ---
function run_sysbench_loadtest() {
  local -r mysql_dir="$1"
  echo "Running sysbench load test (Workload Only)..."
  
  # Configurations are now hardcoded to match the desired profile:
  local -r iterations=8
  local -r small_table_size=10000
  local -r small_events=2500
  local -r large_table_size=500000
  local -r large_events=30000
  local -r args="--range_selects=off --skip_trx"

  run_sysbench_test_full "$mysql_dir" "oltp_delete" "$iterations" "$small_table_size" "$small_events" "$args"
  run_sysbench_test_full "$mysql_dir" "select_random_ranges" "$iterations" "$small_table_size" "$small_events" "$args"
  run_sysbench_test_full "$mysql_dir" "oltp_read_write" "$iterations" "$small_table_size" "$small_events" "$args"
  run_sysbench_test_full "$mysql_dir" "oltp_update_index" "$iterations" "$small_table_size" "$small_events" "$args"
  # run_sysbench_test_full "$mysql_dir" "oltp_read_only" "$iterations" "$large_table_size" "$large_events" "$args"
}

# --- This function is called by 'benchmark' mode (for bisection) ---
function run_sysbench_benchmark() {
  set -e
  local -r mysql_dir="$1"
  shift
  local -r iterations="$1"
  
  run_sysbench_test_full "$mysql_dir" "oltp_read_write" "$iterations" 10000 2500 "--range_selects=off --skip_trx"
  run_sysbench_test_full "$mysql_dir" "oltp_update_index" "$iterations" 10000 2500 "--range_selects=off --skip_trx"
  run_sysbench_test_full "$mysql_dir" "oltp_delete" "$iterations" 10000 2500 "--range_selects=off --skip_trx"
  run_sysbench_test_full "$mysql_dir" "select_random_ranges" "$iterations" 10000 2500 "--range_selects=off --skip_trx"
  # run_sysbench_test_full "$mysql_dir" "oltp_read_only" "$iterations" 500000 30000 "--range_selects=off --skip_trx"
  
  local -a benchmarks=(oltp_read_write oltp_update_index oltp_delete select_random_ranges)
  local -r log_dir="bench.dir/${mysql_dir}"
  for bn in "${benchmarks[@]}"; do
    local table_name="sbtest1"
    
    rm -f "sysbench.${bn}.transPerSec"
    rm -f "sysbench.${bn}.time"
    for i in $(seq 1 "$iterations") ; do
      # Check if log file exists before trying to parse it
      if [ -f "${log_dir}"/"${bn}."${i}.log ]; then
        sed -nEe 's!^\s+transactions:\s+.*\((.*) per sec\.\)$!\1!p' "${log_dir}"/"${bn}."${i}.log >> "sysbench.${bn}.transPerSec"
        sed -nEe 's!^\s+total time:\s+(.*)s$!\1!p' "${log_dir}"/"${bn}."${i}.log >> "sysbench.${bn}.time"
      fi
    done
  done
}