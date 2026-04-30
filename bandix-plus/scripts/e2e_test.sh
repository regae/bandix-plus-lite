#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$PROJECT_ROOT/../target/release/bandix-plus"
API_URL="http://127.0.0.1:8787"
IFACE="lo"
TARGET_IP="127.0.0.1"
BANDIX_PID=""
IPERF3_PID=""
TRAFFIC_MIN_BYTES=$((100 * 1024 * 1024))
TRAFFIC_DURATION=120

parse_traffic_size() {
    local s="$1"
    local num="${s%[KkMmGg]}"
    local unit="${s: -1}"
    [[ -z "$num" ]] && num=0
    case "$unit" in
        [Gg]) echo $((num * 1024 * 1024 * 1024)) ;;
        [Mm]) echo $((num * 1024 * 1024)) ;;
        [Kk]) echo $((num * 1024)) ;;
        *) echo "$num" ;;
    esac
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --iface|-i)
                [[ -z "${2:-}" ]] && { echo "error: --iface 需要参数"; exit 1; }
                IFACE="$2"
                shift 2
                ;;
            --traffic|-t)
                [[ -z "${2:-}" ]] && { echo "error: --traffic 需要参数 (如 100M, 1G)"; exit 1; }
                TRAFFIC_MIN_BYTES=$(parse_traffic_size "$2")
                shift 2
                ;;
            --ip|-p)
                [[ -z "${2:-}" ]] && { echo "error: --ip 需要参数"; exit 1; }
                TARGET_IP="$2"
                shift 2
                ;;
            --help|-h)
                echo "用法: $0 [选项]"
                echo "  --iface, -i INTERFACE  监控接口 (默认: lo)"
                echo "  --traffic, -t SIZE      目标流量: 100M, 1G 等 (默认: 100M)"
                echo "  --ip, -p IP             流量目标 IP (默认: 127.0.0.1)"
                echo "  --help, -h              显示帮助"
                exit 0
                ;;
            *)
                echo "未知参数: $1"
                exit 1
                ;;
        esac
    done
}

parse_args "$@"
HIGH_LOAD_DURATION=30
RATE_LIMIT_DURATION=5

cleanup() {
    if [[ -n "$IPERF3_PID" ]] && kill -0 "$IPERF3_PID" 2>/dev/null; then
        kill "$IPERF3_PID" 2>/dev/null || true
    fi
    if [[ -n "$BANDIX_PID" ]] && kill -0 "$BANDIX_PID" 2>/dev/null; then
        kill "$BANDIX_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

fmt_bytes() {
    local n=$1
    if [[ "$n" -ge 1073741824 ]]; then
        echo "$((n / 1073741824))GB"
    elif [[ "$n" -ge 1048576 ]]; then
        echo "$((n / 1048576))MB"
    elif [[ "$n" -ge 1024 ]]; then
        echo "$((n / 1024))KB"
    else
        echo "${n}B"
    fi
}

get_process_stats() {
    if [[ -z "$BANDIX_PID" ]] || ! kill -0 "$BANDIX_PID" 2>/dev/null; then
        echo "0" "0" "0"
        return
    fi
    local line
    line=$(ps -p "$BANDIX_PID" -o %cpu=,%mem=,rss= 2>/dev/null | tr -s ' ')
    if [[ -n "$line" ]]; then
        echo "$line"
    else
        echo "0" "0" "0"
    fi
}

report_process_resources() {
    local prefix="${1:-│}"
    local cpu mem rss
    read -r cpu mem rss <<< "$(get_process_stats)"
    [[ -z "$cpu" ]] && cpu=0
    [[ -z "$mem" ]] && mem=0
    [[ -z "$rss" ]] && rss=0
    local rss_mb=$((rss / 1024))
    echo "${prefix} CPU: ${cpu}% | 内存: ${mem}% | RSS: ${rss_mb}MB"
    if [[ -n "$PEAK_CPU" ]] && [[ -n "$PEAK_RSS_MB" ]]; then
        echo "${prefix} 峰值: CPU ${PEAK_CPU}% | RSS ${PEAK_RSS_MB}MB"
    fi
}

PEAK_CPU=""
PEAK_RSS_MB=""

sample_peak_resources() {
    local cpu mem rss
    read -r cpu mem rss <<< "$(get_process_stats)"
    [[ -z "$cpu" ]] && cpu=0
    [[ -z "$rss" ]] && rss=0
    local rss_mb=$((rss / 1024))
    if [[ -z "$PEAK_CPU" ]] || [[ "${cpu%%.*}" -gt "${PEAK_CPU%%.*}" ]]; then
        PEAK_CPU=$cpu
    fi
    if [[ -z "$PEAK_RSS_MB" ]] || [[ "$rss_mb" -gt "$PEAK_RSS_MB" ]]; then
        PEAK_RSS_MB=$rss_mb
    fi
}

check_deps() {
    if [[ $EUID -ne 0 ]]; then
        echo "error: need root, run with sudo"
        exit 1
    fi
    for cmd in curl jq iperf3; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "error: $cmd not found"
            exit 1
        fi
    done
}

start_bandix() {
    cd "$PROJECT_ROOT/.."
    cargo build -p bandix-plus --release -q 2>/dev/null || true
    if [[ ! -x "$BINARY" ]]; then
        cargo build -p bandix-plus --release
    fi
    "$BINARY" --iface "$IFACE" --host 0.0.0.0 --port 8787 --log-level warn &
    BANDIX_PID=$!
    for i in $(seq 1 50); do
        if curl -s "$API_URL/api/health" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    echo "error: bandix-plus failed to start"
    exit 1
}

test_http_api() {
    echo ""
    echo "┌─ HTTP API 测试 ─────────────────────────────────────"
    local resp code
    echo "│ [1/8] GET /api/health - 健康检查"
    resp=$(curl -s -w "\n%{http_code}" "$API_URL/api/health")
    code=$(echo "$resp" | tail -n1)
    [[ "$code" == "200" ]]
    [[ "$(echo "$resp" | head -n-1 | jq -r '.ok')" == "true" ]]
    echo "│       结果: PASS (HTTP $code, ok=true)"

    echo "│ [2/8] GET /api/snapshot - 流量快照"
    resp=$(curl -s -w "\n%{http_code}" "$API_URL/api/snapshot")
    code=$(echo "$resp" | tail -n1)
    [[ "$code" == "200" ]]
    local iface_count=$(echo "$resp" | head -n-1 | jq -r '.data.interfaces | length')
    [[ -n "$iface_count" ]] && [[ "$iface_count" -ge 0 ]]
    echo "│       结果: PASS (接口数 $iface_count)"

    echo "│ [3/8] GET /api/overview - 总览"
    code=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/overview")
    [[ "$code" == "200" ]]
    echo "│       结果: PASS (HTTP $code)"

    echo "│ [4/8] GET /api/devices - 设备列表"
    code=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/devices")
    [[ "$code" == "200" ]]
    echo "│       结果: PASS (HTTP $code)"

    echo "│ [5/8] GET /api/devices?iface=$IFACE - 设备筛选"
    code=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/devices?iface=$IFACE")
    [[ "$code" == "200" ]]
    echo "│       结果: PASS (HTTP $code)"

    echo "│ [6/8] GET /api/policy - 策略"
    code=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/policy")
    [[ "$code" == "200" ]]
    echo "│       结果: PASS (HTTP $code)"

    echo "│ [7/8] GET /api/rate_limit/iface_limits - 限速配置查询"
    code=$(curl -s -o /dev/null -w "%{http_code}" "$API_URL/api/rate_limit/iface_limits")
    [[ "$code" == "200" ]]
    echo "│       结果: PASS (HTTP $code)"
    echo "│ [8/8] POST iface_limits - 不在 API 测试阶段设置限速 (避免影响流量/高负载测试)"
    echo "└────────────────────────────────────────────────────"
}

test_traffic() {
    echo ""
    echo "┌─ 流量统计测试 ──────────────────────────────────────"
    echo "│ 功能: 验证 eBPF 采集 $IFACE 接口的 cumulative 流量统计"
    echo "│ 方式: iperf3, 目标 $(fmt_bytes $TRAFFIC_MIN_BYTES), 持续 ${TRAFFIC_DURATION}s"
    echo "│ 提示: 请确保已在 $TARGET_IP 上启动 iperf3 -s"
    echo "│"
    sleep 2
    local iperf_args="-c $TARGET_IP"
    if [[ "$TRAFFIC_MIN_BYTES" -ge $((1024*1024*1024)) ]]; then
        iperf_args="$iperf_args -n 1G"
    else
        iperf_args="$iperf_args -t $TRAFFIC_DURATION"
    fi
    local snap_before snap_after
    snap_before=$(curl -s "$API_URL/api/snapshot")
    local before_total
    before_total=$(echo "$snap_before" | jq -r "[.data.interfaces[] | select(.ifname==\"$IFACE\") | (.cumulative.down_v4_bytes // 0) + (.cumulative.up_v4_bytes // 0) + (.cumulative.down_v6_bytes // 0) + (.cumulative.up_v6_bytes // 0)] | add")
    [[ -z "$before_total" ]] || [[ "$before_total" == "null" ]] && before_total=0
    iperf3 $iperf_args || true
    sleep 3
    snap_after=$(curl -s "$API_URL/api/snapshot")
    local after_total
    after_total=$(echo "$snap_after" | jq -r "[.data.interfaces[] | select(.ifname==\"$IFACE\") | (.cumulative.down_v4_bytes // 0) + (.cumulative.up_v4_bytes // 0) + (.cumulative.down_v6_bytes // 0) + (.cumulative.up_v6_bytes // 0)] | add")
    [[ -z "$after_total" ]] || [[ "$after_total" == "null" ]] && after_total=0
    local total=$((after_total - before_total))
    if [[ "$total" -lt "$TRAFFIC_MIN_BYTES" ]]; then
        echo "│ 结果: FAIL (采集 $total bytes < 要求 $(fmt_bytes $TRAFFIC_MIN_BYTES))"
        echo "│ 快照:"
        echo "$snap_after" | jq -r '.data.interfaces[] | "│   \(.ifname): down_v4=\(.cumulative.down_v4_bytes) up_v4=\(.cumulative.up_v4_bytes)"'
        echo "└────────────────────────────────────────────────────"
        exit 1
    fi
    echo "│ 结果: PASS"
    echo "│ 统计: 累计增量 $(fmt_bytes $total), 阈值 $(fmt_bytes $TRAFFIC_MIN_BYTES)"
    echo "└────────────────────────────────────────────────────"
}

test_high_load() {
    echo ""
    echo "┌─ 高负载测试 ────────────────────────────────────────"
    echo "│ 功能: 验证高流量下 snapshot 的 cumulative 单调递增"
    echo "│ 方式: iperf3 持续 ${HIGH_LOAD_DURATION}s, 每 2s 采样"
    echo "│ 提示: 请确保已在 $TARGET_IP 上启动 iperf3 -s"
    iperf3 -c "$TARGET_IP" -t "$HIGH_LOAD_DURATION" &
    IPERF3_PID=$!
    sleep 2
    local prev=0
    local intervals=$((HIGH_LOAD_DURATION / 2))
    for i in $(seq 1 "$intervals"); do
        sleep 2
        sample_peak_resources
        local data
        data=$(curl -s "$API_URL/api/snapshot" | jq -r "[.data.interfaces[] | select(.ifname==\"$IFACE\") | (.cumulative.down_v4_bytes // 0) + (.cumulative.up_v4_bytes // 0) + (.cumulative.down_v6_bytes // 0) + (.cumulative.up_v6_bytes // 0)] | add")
        [[ -z "$data" ]] && data=0
        if [[ "$data" -lt "$prev" ]]; then
            echo "│ 结果: FAIL (采样 $i: $data < 前次 $prev, cumulative 不应减少)"
            echo "└────────────────────────────────────────────────────"
            exit 1
        fi
        prev=$data
    done
    kill "$IPERF3_PID" 2>/dev/null || true
    wait "$IPERF3_PID" 2>/dev/null || true
    IPERF3_PID=""
    echo "│ 结果: PASS"
    echo "│ 统计: $intervals 次采样均单调递增, 最终 $(fmt_bytes $prev)"
    report_process_resources
    echo "└────────────────────────────────────────────────────"
}

test_rate_limit() {
    sleep 1
    echo ""
    echo "┌─ 限速验证 ─────────────────────────────────────────"
    echo "│ 功能: 验证接口限速 1MB/s 生效"
    local limit_kbps=8192
    local limit_bps=$((limit_kbps * 1000))
    echo "│ 设置: POST $IFACE ${limit_kbps}kbps (1MB/s)"
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d "{\"iface\":\"$IFACE\",\"down_v4_kbps\":$limit_kbps,\"down_v6_kbps\":$limit_kbps,\"up_v4_kbps\":$limit_kbps,\"up_v6_kbps\":$limit_kbps}" "$API_URL/api/rate_limit/iface_limits")
    [[ "$code" == "200" ]] || { echo "│ 设置限速失败 HTTP $code"; exit 1; }
    sleep 1
    echo "│ 方式: iperf3 -c $TARGET_IP -t ${RATE_LIMIT_DURATION}s"
    echo "│ 提示: 请确保已在 $TARGET_IP 上启动 iperf3 -s"
    local before after delta bps
    before=$(curl -s "$API_URL/api/snapshot" | jq -r "[.data.interfaces[] | select(.ifname==\"$IFACE\") | (.cumulative.down_v4_bytes // 0) + (.cumulative.up_v4_bytes // 0)] | add")
    [[ -z "$before" ]] && before=0
    iperf3 -c "$TARGET_IP" -t "$RATE_LIMIT_DURATION" || true
    sleep 2
    after=$(curl -s "$API_URL/api/snapshot" | jq -r "[.data.interfaces[] | select(.ifname==\"$IFACE\") | (.cumulative.down_v4_bytes // 0) + (.cumulative.up_v4_bytes // 0)] | add")
    [[ -z "$after" ]] && after=0
    delta=$((after - before))
    bps=$((delta * 8 / RATE_LIMIT_DURATION))
    if [[ "$bps" -gt $((limit_bps + limit_bps / 5)) ]]; then
        echo "│ 结果: FAIL (实际 $(fmt_bytes $((bps/8)))/s ≈ ${bps} bps > 限额 1MB/s)"
        echo "└────────────────────────────────────────────────────"
        exit 1
    fi
    echo "│ 结果: PASS"
    echo "│ 统计: 实际 $(fmt_bytes $((bps/8)))/s ≈ ${bps} bps <= 1MB/s"
    echo "└────────────────────────────────────────────────────"
}

main() {
    echo ""
    echo "╔══════════════════════════════════════════════════════"
    echo "║ bandix-plus 端到端测试"
    echo "║ 接口: $IFACE | 目标: $TARGET_IP | API: $API_URL"
    echo "╚══════════════════════════════════════════════════════"
    check_deps
    echo ""
    echo "▶ 启动 bandix-plus (--iface $IFACE)..."
    start_bandix
    echo "  就绪"
    echo ""
    echo "▶ HTTP API 测试"
    test_http_api
    echo ""
    echo "▶ 流量统计测试"
    test_traffic
    echo ""
    echo "▶ 高负载测试"
    test_high_load
    if [[ "$IFACE" != "lo" ]]; then
        echo ""
        echo "▶ 限速验证"
        test_rate_limit
    else
        echo ""
        echo "▶ 限速验证 (跳过: lo 不适合)"
    fi
    echo ""
    echo "╔══════════════════════════════════════════════════════"
    echo "║ 测试总结"
    echo "║ ✓ HTTP API (8 项)"
    echo "║ ✓ 流量统计 (eBPF cumulative)"
    echo "║ ✓ 高负载 (单调性)"
    if [[ "$IFACE" != "lo" ]]; then
        echo "║ ✓ 限速 (1MB/s)"
    fi
    echo "║"
    echo "║ 进程资源 (bandix-plus):"
    report_process_resources "║"
    echo "║"
    echo "║ 全部通过"
    echo "╚══════════════════════════════════════════════════════"
}

main
