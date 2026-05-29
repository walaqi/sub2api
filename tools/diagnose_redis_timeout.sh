#!/usr/bin/env bash
# diagnose_redis_timeout.sh
#
# Sub2API 高峰期 Redis read_timeout / "验证码过期" 排查脚本
# 仅做只读采集, 不修改任何系统配置.
#
# 用法:
#   sudo bash diagnose_redis_timeout.sh                    # 默认采样 30s
#   sudo bash diagnose_redis_timeout.sh --duration 60      # 采样 60s
#   sudo bash diagnose_redis_timeout.sh --proc sub2api     # 指定进程名
#   sudo bash diagnose_redis_timeout.sh --redis-port 6379  # 指定 Redis 端口
#   sudo bash diagnose_redis_timeout.sh --webproc nginx    # 另一个 web 进程的名字, 用于估算长连接占用
#
# 建议: 在高峰期跑, 数据最有诊断价值.
# 输出会同时打印到屏幕并保存到 /tmp/sub2api-diag-YYYYmmdd-HHMMSS.txt
#
# 退出码: 0 成功; 1 参数错误; 2 关键命令缺失.

set -u
LC_ALL=C
export LC_ALL

# ---------- 默认参数 ----------
DURATION=30
PROC_NAME="sub2api"
REDIS_PORT=6379
REDIS_HOST="127.0.0.1"
WEB_PROC=""

# ---------- 参数解析 ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration)   DURATION="$2"; shift 2 ;;
    --proc)       PROC_NAME="$2"; shift 2 ;;
    --redis-port) REDIS_PORT="$2"; shift 2 ;;
    --redis-host) REDIS_HOST="$2"; shift 2 ;;
    --webproc)    WEB_PROC="$2"; shift 2 ;;
    -h|--help)
      sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

OUT="/tmp/sub2api-diag-$(date +%Y%m%d-%H%M%S).txt"

# tee 到日志文件, 同时打印
exec > >(tee -a "$OUT") 2>&1

# ---------- 工具函数 ----------
sec()  { printf "\n========== %s ==========\n" "$*"; }
sub()  { printf "\n----- %s -----\n" "$*"; }
note() { printf "[note] %s\n" "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

run() {
  printf "\n$ %s\n" "$*"
  # shellcheck disable=SC2294
  eval "$@" 2>&1 || printf "[exit %d]\n" "$?"
}

# 安全 sysctl: 不存在不报错
sctl() {
  local k="$1"
  local v
  v=$(sysctl -n "$k" 2>/dev/null) || { printf "%s = <unavailable>\n" "$k"; return; }
  printf "%s = %s\n" "$k" "$v"
}

# ---------- 0. 环境信息 ----------
sec "0. 环境信息 / Environment"
date
uname -a
have lsb_release && lsb_release -a 2>/dev/null
run "cat /etc/os-release | head -5"
run "uptime"
run "nproc"
run "free -h"

# ---------- 1. 找进程 ----------
sec "1. 定位 sub2api 进程"
PID=""
if have pgrep; then
  # 取第一个匹配进程, 优先精确匹配 comm
  PID=$(pgrep -x "$PROC_NAME" | head -1)
  if [[ -z "$PID" ]]; then
    PID=$(pgrep -f "$PROC_NAME" | head -1)
  fi
fi

if [[ -z "$PID" ]]; then
  note "未找到进程 '$PROC_NAME'. 请用 --proc <name> 指定."
  note "继续执行, 但进程相关检查会跳过."
else
  echo "PID = $PID"
  run "ps -o pid,ppid,user,pcpu,pmem,rss,vsz,nlwp,etime,cmd -p $PID"
fi

WEB_PID=""
if [[ -n "$WEB_PROC" ]] && have pgrep; then
  WEB_PID=$(pgrep -x "$WEB_PROC" | head -1)
  [[ -z "$WEB_PID" ]] && WEB_PID=$(pgrep -f "$WEB_PROC" | head -1)
  echo "WEB_PID($WEB_PROC) = ${WEB_PID:-<not found>}"
fi

# ---------- 2. 文件描述符 / Open files ----------
sec "2. 文件描述符限制 / FD"
run "ulimit -Hn -Sn"
sctl fs.file-max
sctl fs.nr_open
run "cat /proc/sys/fs/file-nr"
note "file-nr 三列: 已分配 / 已分配但空闲 / 系统上限"

if [[ -n "$PID" ]]; then
  sub "进程 $PID 的 limits"
  run "cat /proc/$PID/limits | grep -E 'open files|processes'"
  if [[ -d "/proc/$PID/fd" ]]; then
    FD_USED=$(ls -U "/proc/$PID/fd" 2>/dev/null | wc -l)
    echo "current open FDs = $FD_USED"
    sub "FD 类型分布 (sample)"
    # 取样统计, 防止 FD 太多卡住
    run "ls -l /proc/$PID/fd 2>/dev/null | awk '{print \$NF}' | awk -F: '{print \$1}' | sort | uniq -c | sort -rn | head -20"
  fi
fi

# ---------- 3. 网络栈 sysctl ----------
sec "3. 内核网络参数 / sysctl"
sub "TCP keepalive (NAT/LB 容易切断空闲连接)"
sctl net.ipv4.tcp_keepalive_time
sctl net.ipv4.tcp_keepalive_intvl
sctl net.ipv4.tcp_keepalive_probes
note "默认 7200/75/9 在云/NAT 网络下偏长, 建议 600/60/3."

sub "Backlog / 连接建立"
sctl net.core.somaxconn
sctl net.ipv4.tcp_max_syn_backlog
sctl net.ipv4.tcp_syncookies
sctl net.ipv4.tcp_synack_retries

sub "Time-wait / 临时端口"
sctl net.ipv4.ip_local_port_range
sctl net.ipv4.tcp_tw_reuse
sctl net.ipv4.tcp_fin_timeout
sctl net.ipv4.tcp_max_tw_buckets

sub "Socket buffer"
sctl net.core.rmem_max
sctl net.core.wmem_max
sctl net.ipv4.tcp_rmem
sctl net.ipv4.tcp_wmem

sub "重传 / 失败检测"
sctl net.ipv4.tcp_retries2
sctl net.ipv4.tcp_retries1

sub "conntrack (NAT/iptables 路径会用)"
sctl net.netfilter.nf_conntrack_max
sctl net.netfilter.nf_conntrack_count
sctl net.netfilter.nf_conntrack_buckets
sctl net.netfilter.nf_conntrack_tcp_timeout_established
sctl net.nf_conntrack_max
note "如果未加载 nf_conntrack 模块, 上面会显示 unavailable, 这种情况下不会因表满丢包."

# ---------- 4. 当前连接状态 ----------
sec "4. 当前 TCP 连接状态快照 (ss)"
have ss || { note "ss 不可用, 跳过."; }
if have ss; then
  run "ss -s"
  sub "Top 20 远端 (ESTABLISHED)"
  run "ss -tan state established | awk '{print \$5}' | awk -F: '{a=\$1\":\"\$2; print a}' | sort | uniq -c | sort -rn | head -20"
  sub "TIME-WAIT 数量"
  run "ss -tan state time-wait | wc -l"
  sub "Redis 连接 (port $REDIS_PORT)"
  run "ss -tanp '( dport = :$REDIS_PORT or sport = :$REDIS_PORT )' 2>/dev/null | head -50"
  run "ss -tan state established '( dport = :$REDIS_PORT or sport = :$REDIS_PORT )' | wc -l"
  if [[ -n "${PID:-}" ]]; then
    sub "sub2api(pid=$PID) 拥有的 socket 状态分布"
    # ss -p 需要 root
    run "ss -tanp 2>/dev/null | grep -E \"pid=$PID(,|\\\\b)\" | awk '{print \$1}' | sort | uniq -c | sort -rn"
  fi
fi

# ---------- 5. dmesg 内核报错 ----------
sec "5. 内核日志 / dmesg (近期网络/内存错误)"
if have dmesg; then
  run "dmesg -T 2>/dev/null | tail -300 | grep -iE 'conntrack|nf_conntrack|too many|out of mem|oom|killed process|tcp:|TCP:|drop' | tail -80"
  note "如出现 'nf_conntrack: table full' 或 'TCP: out of memory' 就是直接证据."
else
  note "dmesg 不可用."
fi

# journalctl 也可能有 OOM
if have journalctl; then
  sub "journalctl 最近 OOM/killed"
  run "journalctl -k --since '24 hours ago' 2>/dev/null | grep -iE 'oom|killed process|out of memory' | tail -20"
fi

# ---------- 6. cgroup / systemd 限制 ----------
sec "6. systemd / cgroup 限制 (裸机也要看, 服务可能被 unit 限了)"
if [[ -n "$PID" ]]; then
  run "cat /proc/$PID/cgroup"
  CG=$(awk -F: 'NR==1{print $3}' "/proc/$PID/cgroup" 2>/dev/null)
  if [[ -n "$CG" && -d "/sys/fs/cgroup$CG" ]]; then
    sub "cgroup v2 状态 ($CG)"
    run "cat /sys/fs/cgroup$CG/cpu.max 2>/dev/null"
    run "cat /sys/fs/cgroup$CG/cpu.stat 2>/dev/null"
    run "cat /sys/fs/cgroup$CG/memory.max 2>/dev/null"
    run "cat /sys/fs/cgroup$CG/memory.current 2>/dev/null"
    run "cat /sys/fs/cgroup$CG/memory.events 2>/dev/null"
  fi
  # systemd unit
  UNIT=$(systemctl status "$PID" 2>/dev/null | head -1 | awk '{print $2}')
  if [[ -n "$UNIT" ]]; then
    sub "systemd unit: $UNIT"
    run "systemctl show '$UNIT' -p LimitNOFILE -p LimitNPROC -p CPUQuota -p MemoryMax -p TasksMax -p Restart 2>/dev/null"
  fi
fi

# ---------- 7. CPU / 内存压力 ----------
sec "7. CPU / 内存 / IO 压力 (PSI)"
run "vmstat 1 5"
[[ -r /proc/pressure/cpu ]]    && run "cat /proc/pressure/cpu"
[[ -r /proc/pressure/memory ]] && run "cat /proc/pressure/memory"
[[ -r /proc/pressure/io ]]     && run "cat /proc/pressure/io"
run "cat /proc/loadavg"
note "PSI some/full avg10 持续 > 10% 就说明该资源在拖累请求."

# ---------- 8. Redis 服务端状态 ----------
sec "8. Redis 服务端状态"
if have redis-cli; then
  REDIS_CLI="redis-cli -h $REDIS_HOST -p $REDIS_PORT"
  if $REDIS_CLI -t 2 ping 2>/dev/null | grep -q PONG; then
    run "$REDIS_CLI INFO clients"
    run "$REDIS_CLI INFO stats | grep -E 'total_connections_received|rejected_connections|instantaneous_ops_per_sec|total_commands_processed|expired_keys|evicted_keys|keyspace_hits|keyspace_misses'"
    run "$REDIS_CLI INFO memory | grep -E 'used_memory_human|used_memory_peak_human|maxmemory_human|maxmemory_policy|mem_fragmentation_ratio'"
    run "$REDIS_CLI INFO commandstats | head -40"
    run "$REDIS_CLI CONFIG GET maxclients"
    run "$REDIS_CLI CONFIG GET timeout"
    run "$REDIS_CLI CONFIG GET tcp-keepalive"
    run "$REDIS_CLI CONFIG GET maxmemory-policy"
    sub "慢查询 (最近 20 条)"
    run "$REDIS_CLI SLOWLOG GET 20"
    sub "实时延迟采样 (3s)"
    run "timeout 3 $REDIS_CLI --latency 2>/dev/null | tail -1"
    sub "延迟 history 1s 间隔 5 次"
    run "timeout 6 $REDIS_CLI --latency-history -i 1 2>/dev/null | head -6"
    # 关键 key 数量
    sub "验证码 / 并发 / 计费 key 计数 (KEYS 仅在小库可用; 用 SCAN 更安全)"
    for prefix in "verify_code:" "concurrency:" "billing:" "rt:"; do
      cnt=$(timeout 5 $REDIS_CLI --scan --pattern "${prefix}*" 2>/dev/null | wc -l)
      printf "  %-20s %s\n" "${prefix}*" "$cnt"
    done
  else
    note "redis-cli 无法连接到 $REDIS_HOST:$REDIS_PORT, 跳过 Redis 服务端检查."
  fi
else
  note "redis-cli 不存在, 跳过 Redis 服务端检查."
fi

# ---------- 9. 进程级 socket / FD 详情 ----------
sec "9. sub2api 进程网络细节"
if [[ -n "$PID" ]] && have ss; then
  sub "按对端端口分布"
  # 用 grep 按 pid=<PID>, 或 pid=<PID>) 字面过滤, 避免 awk 变量与 shell 单引号纠缠.
  run "ss -tanp 2>/dev/null | grep -E 'pid=$PID(,|\))' | awk '{print \$5}' | awk -F: 'NF{print \$NF}' | sort | uniq -c | sort -rn | head -20"
  sub "Recv-Q / Send-Q 非零 (可能在堆积)"
  run "ss -tanp 2>/dev/null | awk 'NR==1 || ((\$2!=0 || \$3!=0) && /pid=$PID(,|\\\\))/)' | head -30"
fi

# 另一个 web 进程的长连接占用估算
if [[ -n "$WEB_PID" ]] && have ss; then
  sub "另一个 web 进程 ($WEB_PROC pid=$WEB_PID) 当前连接数"
  run "ss -tanp 2>/dev/null | grep -cE 'pid=$WEB_PID(,|\))'"
  sub "另一个 web 进程 socket 状态分布"
  run "ss -tanp 2>/dev/null | grep -E 'pid=$WEB_PID(,|\))' | awk '{print \$1}' | sort | uniq -c | sort -rn"
fi

# ---------- 10. 时间窗口采样 ----------
sec "10. 动态采样 ${DURATION}s (高峰期跑这一段最有价值)"
note "采样开始: $(date)"
SAMPLES=$(( DURATION / 5 ))
[[ $SAMPLES -lt 2 ]] && SAMPLES=2

for ((i=1; i<=SAMPLES; i++)); do
  ts=$(date +%H:%M:%S)
  if have ss; then
    tw=$(ss -tan state time-wait 2>/dev/null | wc -l)
    es=$(ss -tan state established 2>/dev/null | wc -l)
    redis_es=$(ss -tan state established "( dport = :$REDIS_PORT or sport = :$REDIS_PORT )" 2>/dev/null | wc -l)
  else
    tw=NA; es=NA; redis_es=NA
  fi
  if [[ -n "${PID:-}" && -d "/proc/$PID/fd" ]]; then
    fd=$(ls -U "/proc/$PID/fd" 2>/dev/null | wc -l)
    pcpu=$(ps -o pcpu= -p "$PID" 2>/dev/null | tr -d ' ')
  else
    fd=NA; pcpu=NA
  fi
  printf "  [%s] tw=%s estab=%s redis_estab=%s sub2api_fd=%s sub2api_cpu=%s%%\n" \
    "$ts" "$tw" "$es" "$redis_es" "$fd" "$pcpu"
  sleep 5
done
note "采样结束: $(date)"

# ---------- 11. Redis 客户端最新连接 ----------
sec "11. Redis CLIENT LIST 摘要 (从大到小看 idle/age)"
if have redis-cli && $REDIS_CLI -t 2 ping 2>/dev/null | grep -q PONG; then
  # 按 age 排序, 取前 30
  run "$REDIS_CLI CLIENT LIST 2>/dev/null | awk '{print \$0}' | head -30"
  sub "CLIENT LIST 总数 / idle 分布"
  run "$REDIS_CLI CLIENT LIST 2>/dev/null | wc -l"
  run "$REDIS_CLI CLIENT LIST 2>/dev/null | awk '{for(i=1;i<=NF;i++){if(\$i ~ /^idle=/){split(\$i,a,\"=\"); print a[2]}}}' | sort -n | awk 'BEGIN{n=0} {a[n++]=\$1} END{ if(n==0){exit}; print \"count=\"n,\"min=\"a[0],\"p50=\"a[int(n/2)],\"p95=\"a[int(n*0.95)],\"max=\"a[n-1]}'"
fi

# ---------- 12. 总结提示 ----------
sec "12. 输出位置"
echo "完整日志已保存到: $OUT"
echo "把这个文件回传给 Claude 即可."

exit 0
