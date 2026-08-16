#!/bin/bash
# ============================================================
# 设计约束：
#   - 不新增原 4 脚本之外的实际测试算法
#   - 自动识别发行版/SSH 版本；识别失败不测试，正常退出
#   - 必须 root（--list 除外）
#   - 默认端口 22
#   - 保留手动模式；--auto 使用本地 127.0.0.1
#   - 每次只修改一个测试配置，测试完成后恢复
#   - 协商结果与认证结果分离
#   - 算法结果不与 SSH 客户端退出码直接绑定
#   - 保留详细测试日志、环境/执行信息、结构化结果
#
# 输出（当前目录）：
#   默认：1 个 CSV + 1 个详细 TXT + 1 个环境/执行 TXT
#   --json：改为 1 个 JSON + 1 个详细 TXT + 1 个环境/执行 TXT
#
# 功能：自动探测当前运行环境（OpenSSH 版本 + init 系统），据此
# 选择并运行对应的算法兼容性测试集，全程共用同一套备份/崩溃自愈/
# 恢复框架。
#
# 环境画像（完全自动探测，不支持手动指定）：
#   centos6   OpenSSH < 6.x + SysV init（如 CentOS 6.10 / OpenSSH 5.3）
#             自动依次运行：SSH-2 遗留算法测试 + SSH-1 协议测试
#             （同一时刻服务器只跑一种协议配置，两套测试不冲突）
#   openssh8  OpenSSH 8.x + systemd（如 AlmaLinux/Rocky 9、Ubuntu 22.04、
#             Debian 12），测试 AlmaLinux 10 构建未启用的 OpenSSH 8.x
#             特有算法（当前只有 curve448-sha512/X448）
#   modern    OpenSSH >= 9.x + systemd（如 AlmaLinux 10），测试现代
#             算法全集（AEAD/CTR/CBC/KEX/HostKey/MAC，含后量子 KEX）
#
# 环境不属于以上任何一类时，脚本不会对系统做任何改动，只打印诊断信息并退出。
#
# 用法（四种模式，所有环境画像下都支持）：
#   sudo ./test_ssh_algorithms_all.sh                # 手动模式（默认，每项测试需手动触发/确认）
#   sudo ./test_ssh_algorithms_all.sh --auto          # 自动模式（本地回环客户端自动触发）
#   sudo ./test_ssh_algorithms_all.sh --list          # 只列出当前环境的测试项，不改动系统
#   sudo ./test_ssh_algorithms_all.sh --only=3        # 只运行编号为 3 的测试项（可与 --auto 组合）
#   sudo ./test_ssh_algorithms_all.sh --only=blowfish # 只运行描述包含 blowfish 的测试项
#
# 安全提示：
#   - 运行期间会临时开启 PermitRootLogin yes / PasswordAuthentication yes。
#   - trap 已覆盖 INT/TERM/EXIT，正常退出、Ctrl+C、kill 都会自动恢复配置。
#   - sshd_config 的每一次写入都是"临时文件校验通过后再原子替换"，线上
#     配置任何时刻要么是上一个合法状态、要么是新的合法状态。
#   - 崩溃自愈机制按 init 系统自动选择实现：
#       systemd 环境：systemd drop-in 的 ExecStartPre 钩子，在 sshd.service
#                     每次启动前检查并按需恢复备份（覆盖脚本被 kill -9 /
#                     断电重启等场景）。
#       SysV 环境（如 CentOS 6）：crontab @reboot 尽力而为的开机自愈检查，
#                     不能像 systemd 那样保证抢在 sshd 之前执行，只能做到
#                     "开机后尽快"。
#   - kill -9 / 断电 / 文件系统损坏等极端情况仍可能让配置停留在测试状态，
#     建议运行前用防火墙临时限制 22 端口来源，并确保有控制台/IPMI 等
#     带外访问方式作为最后手段。
# ============================================================

set -u
set -o pipefail

BASE_DIR="$(pwd)"
TS="$(date +%Y%m%d_%H%M%S)"

RESULT_FORMAT="csv"
AUTO=false
LIST_ONLY=false
ONLY_FILTER=""

SSHD_CONFIG="/etc/ssh/sshd_config"
STATE_ROOT="/var/lib/ssh-algo-unified"
STATE_DIR="${STATE_ROOT}/${TS}_$$"
BACKUP_FILE="${STATE_DIR}/sshd_config.backup"
AUTO_KEY="/tmp/algo_test_key.$$"
AUTO_PUB="${AUTO_KEY}.pub"
AUTO_MARKER="algo-test-auto-key"
LOOPBACK_TARGET="root@127.0.0.1"
PORT=22

LOG_FILE="${BASE_DIR}/ssh_algorithm_test_${TS}.txt"
ENV_FILE="${BASE_DIR}/ssh_algorithm_env_${TS}.txt"
CSV_FILE="${BASE_DIR}/ssh_algorithm_results_${TS}.csv"
JSON_FILE="${BASE_DIR}/ssh_algorithm_results_${TS}.json"

RESTORED=false
CLIENT_PID=""
TEST_INDEX=0
RUN_INDEX=0
PASS=0
FAIL=0
UNKNOWN=0
SKIP=0

INITIAL_SERVICE_ACTIVE=false
INITIAL_SERVICE_KNOWN=false
INITIAL_CRYPTO_POLICY=""
CRYPTO_POLICY_CHANGED=false
GENERATED_HOST_KEYS=()
AUTO_AUTH_KEY_ADDED=false
RESTORE_HELPER="/usr/local/sbin/ssh-algo-unified-restore"
PID_FILE="/run/ssh-algo-unified.pid"
SYSTEMD_DROPIN_DIR=""
SYSTEMD_DROPIN_FILE=""
CRON_TAG="# SSH_ALGO_UNIFIED_RECOVERY"
STATE_DIR_CREATED=false
RECOVERY_INSTALLED=false

OS_ID="unknown"
OS_VERSION_ID="unknown"
OS_PRETTY="unknown"
SSH_VERSION_STR=""
SSH_VER=""
SSHD_VER=""
SERVICE="unknown"
INIT="unknown"
PROFILE="unknown"

declare -a DESCS KEXES CIPHERS MACS HOSTKEYS TEST_GROUPS PROTOCOLS

for arg in "$@"; do
    case "$arg" in
        --auto)
            AUTO=true
            ;;
        --list)
            LIST_ONLY=true
            ;;
        --only=*)
            ONLY_FILTER="${arg#--only=}"
            ;;
        --json)
            RESULT_FORMAT="json"
            ;;
        --csv)
            RESULT_FORMAT="csv"
            ;;
        -h|--help)
            cat <<EOF
用法：
  sudo ./ssh_algorithm_negotiation_unified.sh
  sudo ./ssh_algorithm_negotiation_unified.sh --auto
  sudo ./ssh_algorithm_negotiation_unified.sh --list
  sudo ./ssh_algorithm_negotiation_unified.sh --only=编号
  sudo ./ssh_algorithm_negotiation_unified.sh --only=描述关键词
  sudo ./ssh_algorithm_negotiation_unified.sh --json
  sudo ./ssh_algorithm_negotiation_unified.sh --csv

说明：
  默认输出：CSV + 详细日志 TXT + 环境/执行 TXT
  --json：结果文件改为 JSON
EOF
            exit 0
            ;;
        *)
            echo "警告：未识别参数 '$arg'，已忽略" >&2
            ;;
    esac
done

if ! $LIST_ONLY && [[ $EUID -ne 0 ]]; then
    echo "错误：必须以 root 身份运行。"
    exit 1
fi

need_cmd() {
    command -v "$1" >/dev/null 2>&1
}

log() {
    printf '%s\n' "$*" | tee -a "$LOG_FILE"
}

env_log() {
    printf '%s\n' "$*" >> "$ENV_FILE"
}

csv_escape() {
    local s="${1:-}"
    s=${s//\"/\"\"}
    printf '"%s"' "$s"
}

json_escape() {
    local s="${1:-}"
    s=${s//\\/\\\\}
    s=${s//\"/\\\"}
    s=${s//$'\n'/\\n}
    s=${s//$'\r'/\\r}
    s=${s//$'\t'/\\t}
    printf '%s' "$s"
}

die() {
    log "[错误] $*"
    exit 1
}

detect_env() {
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION_ID="${VERSION_ID:-unknown}"
        OS_PRETTY="${PRETTY_NAME:-unknown}"
    elif [[ -r /etc/redhat-release ]]; then
        OS_PRETTY="$(cat /etc/redhat-release)"
        OS_ID="redhat-family"
        OS_VERSION_ID="$(sed -n 's/.*release \([0-9.]*\).*/\1/p' /etc/redhat-release)"
    fi

    if command -v ssh >/dev/null 2>&1; then
        SSH_VERSION_STR="$(ssh -V 2>&1 || true)"
        # 用 bash 内置正则解析版本号，不依赖 sed；同时兼容没有次版本号的
        # 写法（如假设中的 "OpenSSH_10"）
        if [[ "$SSH_VERSION_STR" =~ OpenSSH_([0-9]+)(\.([0-9]+))? ]]; then
            SSH_VER_MAJOR="${BASH_REMATCH[1]}"
            SSH_VER_MINOR="${BASH_REMATCH[3]:-0}"
            SSH_VER="${SSH_VER_MAJOR}.${SSH_VER_MINOR}"
        else
            SSH_VER=""
            SSH_VER_MAJOR=""
        fi
    else
        SSH_VERSION_STR="未找到 ssh 客户端"
        SSH_VER=""
        SSH_VER_MAJOR=""
    fi
    if command -v sshd >/dev/null 2>&1; then
        SSHD_VER="$(sshd -V 2>&1 | head -1 || true)"
    else
        SSHD_VER="未找到 sshd"
    fi

    if command -v systemctl >/dev/null 2>&1; then
        INIT="systemd"
        # 不同 systemd 版本对"传参但查无此单元"时的退出码不一致（有的
        # 返回 0 只是列表为空），靠退出码判断不可靠；改成对完整列表结果
        # 做字符串匹配，任何 systemd 版本下都准确。
        local unit_list
        unit_list="$(systemctl list-unit-files 2>/dev/null || true)"
        if printf '%s\n' "$unit_list" | grep -q '^sshd\.service'; then
            SERVICE="sshd"
        elif printf '%s\n' "$unit_list" | grep -q '^ssh\.service'; then
            SERVICE="ssh"
        fi
    elif command -v service >/dev/null 2>&1; then
        INIT="sysv/service"
        SERVICE="sshd"
    fi

    # ---- 画像判定：以 OpenSSH 主版本号 + init 系统为准，不依赖
    # /etc/os-release（很多精简版 CentOS 6 根本没有这个文件，靠发行版
    # 名称判定会把 CentOS 6 误判成 modern，拿 OpenSSH 5.3 去跑现代算法
    # 全灭）。OS_ID/OS_PRETTY 仅用于日志展示，不参与判定。
    #
    # 没有可用的服务管理命令（systemctl/service 都不存在）时，无法重启
    # /查询 sshd 状态，即使版本号匹配也判 unknown，避免后面每一项测试
    # 都因为"不知道怎么重启服务"而失败。
    if [[ "$INIT" == "unknown" ]]; then
        PROFILE="unknown"
        return 1
    fi

    if [[ -n "$SSH_VER_MAJOR" ]] && (( SSH_VER_MAJOR < 6 )) && [[ "$INIT" == "sysv/service" ]]; then
        PROFILE="centos6"
        return 0
    fi

    if [[ "$SSH_VER" =~ ^8\. ]]; then
        PROFILE="openssh8"
        return 0
    fi

    if [[ -n "$SSH_VER_MAJOR" ]] && (( SSH_VER_MAJOR >= 9 )); then
        PROFILE="modern"
        return 0
    fi

    PROFILE="unknown"
    return 1
}

add_test() {
    DESCS+=("$1")
    KEXES+=("$2")
    CIPHERS+=("$3")
    MACS+=("$4")
    HOSTKEYS+=("$5")
    TEST_GROUPS+=("$6")
    PROTOCOLS+=("$7")
    TEST_INDEX=$((TEST_INDEX + 1))
}

# ============================================================
# 原 test_algorithms.sh：实际启用的 test_algo 项
# ============================================================
load_modern_tests() {
    local CHACHA="chacha20-poly1305@openssh.com"
    local G256="aes256-gcm@openssh.com"
    local G128="aes128-gcm@openssh.com"
    local H256E="hmac-sha2-256-etm@openssh.com"
    local H512E="hmac-sha2-512-etm@openssh.com"
    local U128E="umac-128-etm@openssh.com"
    local U64E="umac-64-etm@openssh.com"
    local H1E="hmac-sha1-etm@openssh.com"
    local H196E="hmac-sha1-96-etm@openssh.com"
    local M5E="hmac-md5-etm@openssh.com"
    local M596E="hmac-md5-96-etm@openssh.com"
    local U128="umac-128@openssh.com"
    local U64="umac-64@openssh.com"
    local COLD="curve25519-sha256@libssh.org"

    add_test "chacha20-poly1305" \
        "curve25519-sha256" "$CHACHA" "$H256E" "ssh-ed25519" "Cipher/AEAD" 2
    add_test "aes256-gcm" \
        "curve25519-sha256" "$G256" "$H256E" "ssh-ed25519" "Cipher/AEAD" 2
    add_test "aes128-gcm" \
        "curve25519-sha256" "$G128" "$H256E" "ssh-ed25519" "Cipher/AEAD" 2

    add_test "aes256-ctr" \
        "curve25519-sha256" "aes256-ctr" "$H256E" "ssh-ed25519" "Cipher/CTR" 2
    add_test "aes192-ctr" \
        "curve25519-sha256" "aes192-ctr" "$H256E" "ssh-ed25519" "Cipher/CTR" 2
    add_test "aes128-ctr" \
        "curve25519-sha256" "aes128-ctr" "$H256E" "ssh-ed25519" "Cipher/CTR" 2

    add_test "aes256-cbc" \
        "curve25519-sha256" "aes256-cbc" "hmac-sha2-512" "ssh-ed25519" "Cipher/CBC" 2
    add_test "aes192-cbc" \
        "curve25519-sha256" "aes192-cbc" "hmac-sha1" "ssh-ed25519" "Cipher/CBC" 2
    add_test "aes128-cbc" \
        "curve25519-sha256" "aes128-cbc" "hmac-sha1-96" "ssh-ed25519" "Cipher/CBC" 2
    add_test "3des-cbc (Sweet32)" \
        "curve25519-sha256" "3des-cbc" "hmac-md5" "ssh-ed25519" "Cipher/CBC" 2

    add_test "mlkem768x25519-sha256 (后量子+ECDH)" \
        "mlkem768x25519-sha256" "aes256-ctr" "hmac-sha2-256" "ssh-ed25519" "KEX" 2
    add_test "sntrup761x25519-sha512@openssh.com (后量子+ECDH)" \
        "sntrup761x25519-sha512@openssh.com" "aes256-ctr" "hmac-sha2-256" "ssh-ed25519" "KEX" 2
    add_test "sntrup761x25519-sha512 (后量子+ECDH, 无后缀)" \
        "sntrup761x25519-sha512" "aes256-ctr" "hmac-sha2-256" "ssh-ed25519" "KEX" 2
    add_test "curve25519-sha256" \
        "curve25519-sha256" "aes256-ctr" "hmac-sha2-256" "ssh-ed25519" "KEX" 2
    add_test "curve25519-sha256 (旧别名)" \
        "$COLD" "aes256-ctr" "hmac-sha2-256" "ssh-ed25519" "KEX" 2
    add_test "ecdh-sha2-nistp521" \
        "ecdh-sha2-nistp521" "aes256-ctr" "hmac-sha2-256" "ssh-ed25519" "KEX" 2
    add_test "ecdh-sha2-nistp384" \
        "ecdh-sha2-nistp384" "aes256-ctr" "hmac-sha2-256" "ssh-ed25519" "KEX" 2
    add_test "ecdh-sha2-nistp256" \
        "ecdh-sha2-nistp256" "aes256-ctr" "hmac-sha2-256" "ssh-ed25519" "KEX" 2
    add_test "diffie-hellman-group18-sha512 (8192-bit)" \
        "diffie-hellman-group18-sha512" "aes256-ctr" "hmac-sha2-256" "ssh-ed25519" "KEX" 2
    add_test "diffie-hellman-group16-sha512 (4096-bit)" \
        "diffie-hellman-group16-sha512" "aes256-ctr" "hmac-sha2-256" "ssh-ed25519" "KEX" 2
    add_test "diffie-hellman-group14-sha256 (2048-bit)" \
        "diffie-hellman-group14-sha256" "aes256-ctr" "hmac-sha2-256" "ssh-ed25519" "KEX" 2
    add_test "diffie-hellman-group-exchange-sha256" \
        "diffie-hellman-group-exchange-sha256" "aes256-ctr" "hmac-sha2-256" "ssh-ed25519" "KEX" 2
    add_test "diffie-hellman-group14-sha1 (2048-bit, SHA-1)" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-sha2-256" "ssh-ed25519" "KEX" 2
    add_test "diffie-hellman-group-exchange-sha1" \
        "diffie-hellman-group-exchange-sha1" "aes256-ctr" "hmac-sha1" "ssh-ed25519" "KEX" 2
    add_test "diffie-hellman-group1-sha1 (1024-bit, Logjam)" \
        "diffie-hellman-group1-sha1" "aes256-ctr" "hmac-sha1" "ssh-ed25519" "KEX" 2

    add_test "ssh-ed25519" \
        "curve25519-sha256" "aes256-ctr" "hmac-sha2-256" "ssh-ed25519" "HostKey" 2
    add_test "ecdsa-sha2-nistp521" \
        "curve25519-sha256" "aes256-ctr" "hmac-sha2-256" "ecdsa-sha2-nistp521" "HostKey" 2
    add_test "ecdsa-sha2-nistp384" \
        "curve25519-sha256" "aes256-ctr" "hmac-sha2-256" "ecdsa-sha2-nistp384" "HostKey" 2
    add_test "ecdsa-sha2-nistp256" \
        "curve25519-sha256" "aes256-ctr" "hmac-sha2-256" "ecdsa-sha2-nistp256" "HostKey" 2
    add_test "rsa-sha2-512" \
        "curve25519-sha256" "aes256-ctr" "hmac-sha2-256" "rsa-sha2-512" "HostKey" 2
    add_test "rsa-sha2-256" \
        "curve25519-sha256" "aes256-ctr" "hmac-sha2-256" "rsa-sha2-256" "HostKey" 2
    add_test "ssh-rsa (SHA-1 签名, 已弃用)" \
        "curve25519-sha256" "aes256-ctr" "hmac-sha2-256" "ssh-rsa" "HostKey" 2

    add_test "hmac-sha2-512-etm" \
        "curve25519-sha256" "aes256-ctr" "$H512E" "ssh-ed25519" "MAC" 2
    add_test "hmac-sha2-256-etm" \
        "curve25519-sha256" "aes256-ctr" "$H256E" "ssh-ed25519" "MAC" 2
    add_test "umac-128-etm" \
        "curve25519-sha256" "aes256-ctr" "$U128E" "ssh-ed25519" "MAC" 2
    add_test "umac-64-etm" \
        "curve25519-sha256" "aes256-ctr" "$U64E" "ssh-ed25519" "MAC" 2
    add_test "hmac-sha2-512" \
        "curve25519-sha256" "aes256-ctr" "hmac-sha2-512" "ssh-ed25519" "MAC" 2
    add_test "hmac-sha2-256" \
        "curve25519-sha256" "aes256-ctr" "hmac-sha2-256" "ssh-ed25519" "MAC" 2
    add_test "umac-128" \
        "curve25519-sha256" "aes256-ctr" "$U128" "ssh-ed25519" "MAC" 2
    add_test "umac-64" \
        "curve25519-sha256" "aes256-ctr" "$U64" "ssh-ed25519" "MAC" 2
    add_test "hmac-sha1-etm" \
        "curve25519-sha256" "aes256-ctr" "$H1E" "ssh-ed25519" "MAC" 2
    add_test "hmac-sha1" \
        "curve25519-sha256" "aes256-ctr" "hmac-sha1" "ssh-ed25519" "MAC" 2
    add_test "hmac-sha1-96-etm" \
        "curve25519-sha256" "aes256-ctr" "$H196E" "ssh-ed25519" "MAC" 2
    add_test "hmac-sha1-96" \
        "curve25519-sha256" "aes256-ctr" "hmac-sha1-96" "ssh-ed25519" "MAC" 2
    add_test "hmac-md5-etm" \
        "curve25519-sha256" "aes256-ctr" "$M5E" "ssh-ed25519" "MAC" 2
    add_test "hmac-md5" \
        "curve25519-sha256" "aes256-ctr" "hmac-md5" "ssh-ed25519" "MAC" 2
    add_test "hmac-md5-96-etm" \
        "curve25519-sha256" "aes256-ctr" "$M596E" "ssh-ed25519" "MAC" 2
    add_test "hmac-md5-96" \
        "curve25519-sha256" "aes256-ctr" "hmac-md5-96" "ssh-ed25519" "MAC" 2

    add_test "全遗留: group1 + 3des + md5 + ssh-rsa" \
        "diffie-hellman-group1-sha1" "3des-cbc" "hmac-md5" "ssh-rsa" "Legacy" 2
}

# ============================================================
# 原 test_centos6.sh：实际启用的 test_algo 项
# ============================================================
load_centos6_tests() {
    local RSA="/etc/ssh/ssh_host_rsa_key"
    local DSA="/etc/ssh/ssh_host_dsa_key"

    add_test "blowfish-cbc + hmac-sha1" \
        "diffie-hellman-group14-sha1" "blowfish-cbc" "hmac-sha1" "$RSA" "Cipher" 2
    add_test "cast128-cbc + hmac-sha1" \
        "diffie-hellman-group14-sha1" "cast128-cbc" "hmac-sha1" "$RSA" "Cipher" 2
    add_test "arcfour + hmac-sha1" \
        "diffie-hellman-group14-sha1" "arcfour" "hmac-sha1" "$RSA" "Cipher" 2
    add_test "arcfour256 + hmac-sha1" \
        "diffie-hellman-group14-sha1" "arcfour256" "hmac-sha1" "$RSA" "Cipher" 2
    add_test "arcfour128 + hmac-sha1" \
        "diffie-hellman-group14-sha1" "arcfour128" "hmac-sha1" "$RSA" "Cipher" 2
    add_test "rijndael-cbc + hmac-sha1" \
        "diffie-hellman-group14-sha1" "rijndael-cbc@lysator.liu.se" "hmac-sha1" "$RSA" "Cipher" 2
    add_test "3des-cbc + hmac-sha1" \
        "diffie-hellman-group14-sha1" "3des-cbc" "hmac-sha1" "$RSA" "Cipher" 2
    add_test "aes256-cbc + hmac-sha1" \
        "diffie-hellman-group14-sha1" "aes256-cbc" "hmac-sha1" "$RSA" "Cipher" 2
    add_test "aes128-ctr + hmac-sha1" \
        "diffie-hellman-group14-sha1" "aes128-ctr" "hmac-sha1" "$RSA" "Cipher" 2

    add_test "aes256-ctr + hmac-md5" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-md5" "$RSA" "MAC" 2
    add_test "aes256-ctr + hmac-md5-96" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-md5-96" "$RSA" "MAC" 2
    add_test "aes256-ctr + hmac-sha1-96" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-sha1-96" "$RSA" "MAC" 2
    add_test "aes256-ctr + hmac-ripemd160" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-ripemd160" "$RSA" "MAC" 2
    add_test "aes256-ctr + hmac-ripemd160-etm" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-ripemd160-etm@openssh.com" "$RSA" "MAC" 2
    add_test "aes256-ctr + hmac-ripemd160@openssh.com" \
        "diffie-hellman-group14-sha1" "aes256-ctr" "hmac-ripemd160@openssh.com" "$RSA" "MAC" 2

    add_test "ssh-dss + 3des-cbc + hmac-md5" \
        "diffie-hellman-group14-sha1" "3des-cbc" "hmac-md5" "$DSA" "HostKey" 2
    add_test "ssh-dss + blowfish + hmac-sha1" \
        "diffie-hellman-group14-sha1" "blowfish-cbc" "hmac-sha1" "$DSA" "HostKey" 2
}

# ============================================================
# 原 test_centos6_ssh1.sh：实际启用的 5 项
# ============================================================
load_ssh1_tests() {
    add_test "SSH-1: 3des" "" "3des" "" "/etc/ssh/ssh_host_rsa_key" "SSH-1 Cipher" 1
    add_test "SSH-1: blowfish" "" "blowfish" "" "/etc/ssh/ssh_host_rsa_key" "SSH-1 Cipher" 1
    add_test "SSH-1: idea" "" "idea" "" "/etc/ssh/ssh_host_rsa_key" "SSH-1 Cipher" 1
    add_test "SSH-1: arcfour" "" "arcfour" "" "/etc/ssh/ssh_host_rsa_key" "SSH-1 Cipher" 1
    add_test "SSH-1: des" "" "des" "" "/etc/ssh/ssh_host_rsa_key" "SSH-1 Cipher" 1
}

# ============================================================
# 原 test_openssh8.sh：实际启用的 1 项
# ============================================================
load_openssh8_tests() {
    add_test "curve448-sha512 (X448)" \
        "curve448-sha512" "aes256-ctr" "hmac-sha2-256" "ssh-ed25519" "OpenSSH8/X448" 2
}

if ! detect_env; then
    if $LIST_ONLY; then
        PROFILE="unknown"
    else
        echo "=================================================="
        echo " 环境识别失败：不执行测试，正常退出，不改动任何系统配置。"
        echo "=================================================="
        echo " 系统: ${OS_PRETTY}"
        echo " OpenSSH 客户端: ${SSH_VERSION_STR:-未知}"
        echo " OpenSSH 版本号: ${SSH_VER:-无法解析}"
        echo " init 系统: ${INIT}"
        echo ""
        echo " 本脚本目前只覆盖以下三种画像："
        echo "   1. centos6   OpenSSH < 6.x + SysV/service init（如 CentOS 6.10 / OpenSSH 5.3）"
        echo "   2. openssh8  OpenSSH 8.x + systemd（如 AlmaLinux/Rocky 9、Ubuntu 22.04）"
        echo "   3. modern    OpenSSH >= 9.x + systemd（如 AlmaLinux 10）"
        echo " 当前环境不在以上范围内，或缺少 systemctl/service 等服务管理"
        echo " 命令，说明这不是本脚本设计要测试的算法协商场景。"
        echo "=================================================="
        exit 0
    fi
fi

case "$PROFILE" in
    modern)
        load_modern_tests
        ;;
    centos6)
        load_centos6_tests
        load_ssh1_tests
        ;;
    openssh8)
        # test_openssh8.sh 是在 test_algorithms.sh 主集合之外追加 X448。
        # 因此 OpenSSH 8.x 环境使用主集合 + 原 X448 项。
        load_modern_tests
        load_openssh8_tests
        ;;
    *)
        ;;
esac

if $LIST_ONLY; then
    echo "========================================"
    echo "统一 SSH 算法协商测试项"
    echo "环境：${OS_PRETTY}"
    echo "OpenSSH：${SSH_VERSION_STR:-unknown}"
    echo "Profile：${PROFILE}"
    echo "========================================"
    i=0
    for d in "${DESCS[@]}"; do
        i=$((i + 1))
        printf '%3d. %s\n' "$i" "$d"
    done
    echo "========================================"
    exit 0
fi

: > "$LOG_FILE"
: > "$ENV_FILE"

env_log "SSH 算法协商测试 - 环境/执行信息"
env_log "开始时间: $(date '+%Y-%m-%d %H:%M:%S %Z')"
env_log "当前目录: $BASE_DIR"
env_log "系统: $OS_PRETTY"
env_log "OS_ID: $OS_ID"
env_log "OS_VERSION_ID: $OS_VERSION_ID"
env_log "SSH 客户端版本: $SSH_VERSION_STR"
env_log "SSHD 版本: $SSHD_VER"
env_log "SSH 主版本: ${SSH_VER:-unknown}"
env_log "服务: $SERVICE"
env_log "初始化系统: $INIT"
env_log "测试端口: $PORT"
env_log "测试模式: $($AUTO && echo auto || echo manual)"
env_log "筛选: ${ONLY_FILTER:-全部}"
env_log "Profile: $PROFILE"
env_log "结果格式: $RESULT_FORMAT"

# ============================================================
# 初始服务状态 / crypto-policies 状态记录
# ============================================================
record_initial_state() {
    if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
        if systemctl is-active --quiet "$SERVICE"; then
            INITIAL_SERVICE_ACTIVE=true
        else
            INITIAL_SERVICE_ACTIVE=false
        fi
        INITIAL_SERVICE_KNOWN=true
    elif command -v service >/dev/null 2>&1 && [[ "$SERVICE" != "unknown" ]]; then
        if service "$SERVICE" status >/dev/null 2>&1; then
            INITIAL_SERVICE_ACTIVE=true
        else
            INITIAL_SERVICE_ACTIVE=false
        fi
        INITIAL_SERVICE_KNOWN=true
    fi

    if command -v update-crypto-policies >/dev/null 2>&1; then
        INITIAL_CRYPTO_POLICY="$(update-crypto-policies --show 2>/dev/null || true)"
        if [[ -n "$INITIAL_CRYPTO_POLICY" ]]; then
            env_log "初始 crypto-policy: $INITIAL_CRYPTO_POLICY"
        fi
    fi
}

backup_config() {
    [[ -f "$SSHD_CONFIG" ]] || die "配置文件不存在：$SSHD_CONFIG"
    mkdir -p -m 700 "$STATE_DIR" || die "无法创建状态目录：$STATE_DIR"
    STATE_DIR_CREATED=true
    cp -a "$SSHD_CONFIG" "$BACKUP_FILE" || die "无法备份 $SSHD_CONFIG"
    chmod 600 "$BACKUP_FILE" || true
    env_log "配置备份: $BACKUP_FILE"
    env_log "状态目录: $STATE_DIR"
}

verify_restored_state() {
    local cfg_ok=true svc_ok=true crypto_ok=true temp_ok=true

    if command -v sshd >/dev/null 2>&1; then
        if sshd -t -f "$SSHD_CONFIG" >/dev/null 2>&1; then
            log "[恢复验证] sshd_config: PASS"
        else
            cfg_ok=false
            log "[恢复验证] sshd_config: FAIL（sshd -t 失败）"
        fi
    else
        cfg_ok=false
        log "[恢复验证] sshd_config: UNKNOWN（未找到 sshd）"
    fi

    if $INITIAL_SERVICE_KNOWN; then
        if $INITIAL_SERVICE_ACTIVE; then
            if service_is_up; then
                log "[恢复验证] service state: PASS（运行）"
            else
                svc_ok=false
                log "[恢复验证] service state: FAIL（应运行但未运行）"
            fi
        else
            if service_is_up; then
                svc_ok=false
                log "[恢复验证] service state: FAIL（应停止但仍运行）"
            else
                log "[恢复验证] service state: PASS（停止）"
            fi
        fi
    else
        log "[恢复验证] service state: UNKNOWN（测试前服务状态未知）"
    fi

    if $CRYPTO_POLICY_CHANGED && command -v update-crypto-policies >/dev/null 2>&1 && [[ -n "$INITIAL_CRYPTO_POLICY" ]]; then
        local final_crypto
        final_crypto="$(update-crypto-policies --show 2>/dev/null || true)"
        if [[ "$final_crypto" == "$INITIAL_CRYPTO_POLICY" ]]; then
            log "[恢复验证] crypto-policy: PASS ($final_crypto)"
        else
            crypto_ok=false
            log "[恢复验证] crypto-policy: FAIL（当前='$final_crypto'，期望='$INITIAL_CRYPTO_POLICY'）"
        fi
    fi

    if find /tmp -maxdepth 1 -type f \( -name 'algo_client.*' -o -name 'algo_sshd_t.*' \) -print -quit 2>/dev/null | grep -q .; then
        temp_ok=false
        log "[恢复验证] temporary files: FAIL（发现测试临时文件）"
    else
        log "[恢复验证] temporary files: PASS（CLEAN）"
    fi

    if $cfg_ok && $svc_ok && $crypto_ok && $temp_ok; then
        log "[恢复验证] 总体：PASS"
    else
        log "[恢复验证] 总体：FAIL，请检查上述恢复验证日志"
    fi
}

restore_all() {
    $RESTORED && return
    RESTORED=true

    printf '\n' | tee -a "$LOG_FILE"
    log "[恢复] 开始恢复配置、服务状态和临时文件..."

    if [[ -n "${CLIENT_PID:-}" ]] && kill -0 "$CLIENT_PID" 2>/dev/null; then
        kill "$CLIENT_PID" 2>/dev/null || true
        wait "$CLIENT_PID" 2>/dev/null || true
    fi
    CLIENT_PID=""

    # 自动模式临时公钥只删除本脚本自己添加的那一行，不触碰用户原有 authorized_keys。
    if $AUTO_AUTH_KEY_ADDED && [[ -f /root/.ssh/authorized_keys ]]; then
        local auth_tmp
        auth_tmp="$(mktemp /root/.ssh/authorized_keys.restore.XXXXXX 2>/dev/null || true)"
        if [[ -n "$auth_tmp" ]]; then
            grep -vF "$AUTO_MARKER" /root/.ssh/authorized_keys > "$auth_tmp" 2>/dev/null || true
            chmod 600 "$auth_tmp"
            mv -f "$auth_tmp" /root/.ssh/authorized_keys
            log "[恢复] 自动模式临时公钥已移除"
        fi
    fi
    rm -f "$AUTO_KEY" "$AUTO_PUB"

    # 恢复测试前的 sshd_config；整个恢复过程使用同目录临时文件 + mv，避免半写状态。
    if [[ -f "$BACKUP_FILE" ]]; then
        local restore_tmp
        restore_tmp="$(mktemp "${SSHD_CONFIG}.restore.XXXXXX")"
        if cp -a "$BACKUP_FILE" "$restore_tmp" && mv -f "$restore_tmp" "$SSHD_CONFIG"; then
            log "[恢复] sshd_config 已恢复"
        else
            log "[恢复] ERROR：sshd_config 恢复失败"
            rm -f "$restore_tmp"
        fi
    fi

    # 删除本次运行期间新生成、原本不存在的 host key。
    local hk
    for hk in "${GENERATED_HOST_KEYS[@]}"; do
        rm -f "$hk" "${hk}.pub"
        log "[恢复] 删除本次生成的 HostKey：$hk"
    done

    if $CRYPTO_POLICY_CHANGED && command -v update-crypto-policies >/dev/null 2>&1 && [[ -n "$INITIAL_CRYPTO_POLICY" ]]; then
        local current_crypto=""
        current_crypto="$(update-crypto-policies --show 2>/dev/null || true)"
        if [[ "$current_crypto" == "LEGACY" ]]; then
            if update-crypto-policies --set "$INITIAL_CRYPTO_POLICY" >/dev/null 2>&1; then
                log "[恢复] crypto-policy 已恢复：$INITIAL_CRYPTO_POLICY"
            else
                log "[恢复] ERROR：crypto-policy 恢复失败"
            fi
        else
            log "[恢复] WARNING：crypto-policy 当前为 '$current_crypto'，不是本脚本设置的 LEGACY；跳过恢复，避免覆盖其他进程的修改"
        fi
    fi

    rm -f /tmp/algo_client.* /tmp/algo_sshd_t.*

    # 恢复测试前服务运行状态；不因为脚本测试过程中重启过就改变原状态。
    if $INITIAL_SERVICE_KNOWN; then
        if $INITIAL_SERVICE_ACTIVE; then
            if service_restart; then
                log "[恢复] 服务状态：恢复为测试前运行状态"
            else
                log "[恢复] ERROR：无法恢复 sshd 运行状态"
            fi
        else
            if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
                systemctl stop "$SERVICE" >/dev/null 2>&1 || true
            elif command -v service >/dev/null 2>&1 && [[ "$SERVICE" != "unknown" ]]; then
                service "$SERVICE" stop >/dev/null 2>&1 || true
            fi
            log "[恢复] 服务状态：恢复为测试前停止状态"
        fi
    fi

    # 删除本次运行创建的崩溃自愈钩子和 PID。
    rm -f "$PID_FILE"
    if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
        if [[ -n "$SYSTEMD_DROPIN_FILE" ]]; then rm -f "$SYSTEMD_DROPIN_FILE"; fi
        if [[ -n "$SYSTEMD_DROPIN_DIR" ]]; then rmdir "$SYSTEMD_DROPIN_DIR" 2>/dev/null || true; fi
        rm -f "$RESTORE_HELPER"
        systemctl daemon-reload >/dev/null 2>&1 || true
    elif [[ "$INIT" == "sysv/service" ]] && command -v crontab >/dev/null 2>&1; then
        local cron_now cron_tmp
        cron_now="$(crontab -l 2>/dev/null || true)"
        cron_tmp="$(mktemp /tmp/ssh-algo-unified-cron-clean.XXXXXX 2>/dev/null || true)"
        if [[ -n "$cron_tmp" ]]; then
            printf '%s\n' "$cron_now" | grep -vF "$CRON_TAG" > "$cron_tmp" || true
            crontab "$cron_tmp" 2>/dev/null || true
            rm -f "$cron_tmp"
        fi
        rm -f "$RESTORE_HELPER"
    fi

    verify_restored_state

    if $STATE_DIR_CREATED; then
        rm -rf -- "$STATE_DIR"
        STATE_DIR_CREATED=false
    fi
    log "[恢复] 临时文件和测试客户端已清理"
    log "[恢复] 完成"
}

install_recovery() {
    echo "$$" > "$PID_FILE" || die "无法创建 PID 文件：$PID_FILE"

    if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
        SYSTEMD_DROPIN_DIR="/etc/systemd/system/${SERVICE}.service.d"
        SYSTEMD_DROPIN_FILE="${SYSTEMD_DROPIN_DIR}/ssh-algo-unified.conf"

        local helper_tmp dropin_tmp
        mkdir -p "$(dirname "$RESTORE_HELPER")"
        helper_tmp="$(mktemp "${RESTORE_HELPER}.XXXXXX")" || die "无法创建恢复脚本"
        cat > "$helper_tmp" <<EOF
#!/bin/bash
set -u
CONFIG="$SSHD_CONFIG"
BACKUP="$BACKUP_FILE"
MARKER="# ALGO_TEST_ACTIVE_MARKER_DO_NOT_EDIT"
PIDFILE="$PID_FILE"
SERVICE="$SERVICE"
DROPIN="$SYSTEMD_DROPIN_FILE"
DROPIN_DIR="$SYSTEMD_DROPIN_DIR"
if [[ -f "\$BACKUP" ]] && grep -qF "\$MARKER" "\$CONFIG" 2>/dev/null; then
    restore=false
    if [[ ! -f "\$PIDFILE" ]]; then
        restore=true
    else
        pid="\$(cat "\$PIDFILE" 2>/dev/null || true)"
        if [[ -z "\$pid" ]] || ! kill -0 "\$pid" 2>/dev/null; then restore=true; fi
    fi
    if \$restore; then
        t="\$(mktemp "\${CONFIG}.recover.XXXXXX")"
        if cp -a "\$BACKUP" "\$t"; then
            mv -f "\$t" "\$CONFIG"
            logger -t ssh-algo-unified "检测到异常中止测试配置，已恢复备份" 2>/dev/null || true
            rm -f "\$PIDFILE" "\$BACKUP" "\$DROPIN"
            rmdir "\$DROPIN_DIR" 2>/dev/null || true
            systemctl daemon-reload >/dev/null 2>&1 || true
            systemctl restart "\$SERVICE" >/dev/null 2>&1 || true
        else
            rm -f "\$t"
        fi
    fi
fi
exit 0
EOF
        chmod 755 "$helper_tmp"
        mv -f "$helper_tmp" "$RESTORE_HELPER"
        mkdir -p "$SYSTEMD_DROPIN_DIR"
        dropin_tmp="$(mktemp "${SYSTEMD_DROPIN_FILE}.XXXXXX")" || die "无法创建 systemd recovery drop-in"
        cat > "$dropin_tmp" <<EOF
# SSH algorithm unified test temporary recovery hook
[Service]
ExecStartPre=$RESTORE_HELPER
EOF
        if [[ -f /etc/crypto-policies/back-ends/opensslcnf.config ]]; then
            printf '%s\n' 'Environment=OPENSSL_CONF=/etc/crypto-policies/back-ends/opensslcnf.config' >> "$dropin_tmp"
        fi
        mv -f "$dropin_tmp" "$SYSTEMD_DROPIN_FILE"
        systemctl daemon-reload >/dev/null 2>&1 || true
        RECOVERY_INSTALLED=true

    elif [[ "$INIT" == "sysv/service" && "$SERVICE" != "unknown" ]] && command -v crontab >/dev/null 2>&1; then
        local cron_tmp current
        current="$(crontab -l 2>/dev/null || true)"
        cron_tmp="$(mktemp /tmp/ssh-algo-unified-cron.XXXXXX)"
        printf '%s\n' "$current" | grep -vF "$CRON_TAG" > "$cron_tmp" || true
        printf '@reboot %s %s\n' "$RESTORE_HELPER" "$CRON_TAG" >> "$cron_tmp"
        cat > "${RESTORE_HELPER}.tmp" <<EOF
#!/bin/bash
set -u
CONFIG="$SSHD_CONFIG"
BACKUP="$BACKUP_FILE"
MARKER="# ALGO_TEST_ACTIVE_MARKER_DO_NOT_EDIT"
SERVICE="$SERVICE"
if [[ -f "\$BACKUP" ]] && grep -qF "\$MARKER" "\$CONFIG" 2>/dev/null; then
    t="\$(mktemp "\${CONFIG}.recover.XXXXXX")"
    if cp -a "\$BACKUP" "\$t"; then
        mv -f "\$t" "\$CONFIG"
        service "\$SERVICE" restart >/dev/null 2>&1 || true
    else
        rm -f "\$t"
    fi
fi
exit 0
EOF
        chmod 755 "${RESTORE_HELPER}.tmp"
        mv -f "${RESTORE_HELPER}.tmp" "$RESTORE_HELPER"
        crontab "$cron_tmp" 2>/dev/null || true
        rm -f "$cron_tmp"
        RECOVERY_INSTALLED=true
    fi
}

trap 'restore_all; exit 130' INT
trap 'restore_all; exit 143' TERM
trap restore_all EXIT

record_initial_state
backup_config
install_recovery

prepare_crypto_policy() {
    if [[ "$PROFILE" == "modern" || "$PROFILE" == "openssh8" ]] &&
       command -v update-crypto-policies >/dev/null 2>&1; then
        local before
        before="$(update-crypto-policies --show 2>/dev/null || true)"
        if [[ -n "$before" && "$before" != "LEGACY" ]]; then
            if update-crypto-policies --set LEGACY >/dev/null 2>&1; then
                CRYPTO_POLICY_CHANGED=true
                if [[ -f /etc/crypto-policies/back-ends/opensslcnf.config ]]; then
                    export OPENSSL_CONF="/etc/crypto-policies/back-ends/opensslcnf.config"
                fi
                env_log "crypto-policy: $before -> LEGACY"
            else
                env_log "WARNING: update-crypto-policies --set LEGACY 失败"
            fi
        fi
    fi
}

prepare_host_keys() {
    # 仅在原文件不存在时生成；成功后立即登记。生成失败/半成品全部清理，
    # 避免异常退出留下不完整的系统 HostKey。
    local key path generated_ok
    for key in rsa ed25519 ecdsa dsa; do
        case "$key" in
            rsa) path="/etc/ssh/ssh_host_rsa_key" ;;
            ed25519) path="/etc/ssh/ssh_host_ed25519_key" ;;
            ecdsa) path="/etc/ssh/ssh_host_ecdsa_key" ;;
            dsa) path="/etc/ssh/ssh_host_dsa_key" ;;
        esac
        [[ -f "$path" ]] && continue

        generated_ok=false
        case "$key" in
            rsa) ssh-keygen -q -t rsa -b 4096 -f "$path" -N "" >/dev/null 2>&1 && generated_ok=true ;;
            ed25519) ssh-keygen -q -t ed25519 -f "$path" -N "" >/dev/null 2>&1 && generated_ok=true ;;
            ecdsa) ssh-keygen -q -t ecdsa -b 521 -f "$path" -N "" >/dev/null 2>&1 && generated_ok=true ;;
            dsa) ssh-keygen -q -t dsa -f "$path" -N "" >/dev/null 2>&1 && generated_ok=true ;;
        esac

        if $generated_ok && [[ -f "$path" ]]; then
            GENERATED_HOST_KEYS+=("$path")
            env_log "本次测试新生成 HostKey: $path"
        else
            rm -f "$path" "${path}.pub"
            env_log "WARNING：HostKey 生成失败，已清理半成品：$path"
        fi
    done
}


prepare_auto_key() {
    mkdir -p /root/.ssh
    chmod 700 /root/.ssh

    rm -f "$AUTO_KEY" "$AUTO_PUB"
    ssh-keygen -t ed25519 -f "$AUTO_KEY" -N "" -q || return 1

    touch /root/.ssh/authorized_keys
    local auth_tmp
    auth_tmp="$(mktemp /root/.ssh/authorized_keys.prepare.XXXXXX)" || return 1
    # 同一工具的旧 marker 视为上次异常残留，先移除，再加入本次临时公钥。
    grep -vF "$AUTO_MARKER" /root/.ssh/authorized_keys > "$auth_tmp" 2>/dev/null || true
    printf '%s %s\n' "$(cat "$AUTO_PUB")" "$AUTO_MARKER" >> "$auth_tmp"
    chmod 600 "$auth_tmp"
    mv -f "$auth_tmp" /root/.ssh/authorized_keys
    AUTO_AUTH_KEY_ADDED=true
}

prepare_crypto_policy
prepare_host_keys

if $AUTO; then
    prepare_auto_key || die "无法准备自动模式临时认证密钥"
fi

if [[ "$RESULT_FORMAT" == "csv" ]]; then
    printf '%s\n' \
        'index,description,group,protocol,fixed_kex,fixed_cipher,fixed_mac,fixed_hostkey,negotiated_kex,negotiated_cipher,negotiated_mac,negotiated_hostkey,negotiation_result,authentication_result,client_result,reason' \
        > "$CSV_FILE"
else
    printf '[\n' > "$JSON_FILE"
fi

write_result() {
    local idx="$1" desc="$2" group="$3" proto="$4"
    local fk="$5" fc="$6" fm="$7" fh="$8"
    local nk="$9" nc="${10}" nm="${11}" nh="${12}"
    local nr="${13}" ar="${14}" cr="${15}" reason="${16}"

    if [[ "$RESULT_FORMAT" == "csv" ]]; then
        csv_escape "$idx"; printf ',' >> "$CSV_FILE"
        csv_escape "$desc"; printf ',' >> "$CSV_FILE"
        csv_escape "$group"; printf ',' >> "$CSV_FILE"
        csv_escape "$proto"; printf ',' >> "$CSV_FILE"
        csv_escape "$fk"; printf ',' >> "$CSV_FILE"
        csv_escape "$fc"; printf ',' >> "$CSV_FILE"
        csv_escape "$fm"; printf ',' >> "$CSV_FILE"
        csv_escape "$fh"; printf ',' >> "$CSV_FILE"
        csv_escape "$nk"; printf ',' >> "$CSV_FILE"
        csv_escape "$nc"; printf ',' >> "$CSV_FILE"
        csv_escape "$nm"; printf ',' >> "$CSV_FILE"
        csv_escape "$nh"; printf ',' >> "$CSV_FILE"
        csv_escape "$nr"; printf ',' >> "$CSV_FILE"
        csv_escape "$ar"; printf ',' >> "$CSV_FILE"
        csv_escape "$cr"; printf ',' >> "$CSV_FILE"
        csv_escape "$reason"; printf '\n' >> "$CSV_FILE"
    else
        if (( RUN_INDEX > 1 )); then
            printf ',\n' >> "$JSON_FILE"
        fi
        printf '  {"index":%s,"description":"%s","group":"%s","protocol":"%s","fixed":{"kex":"%s","cipher":"%s","mac":"%s","hostkey":"%s"},"negotiated":{"kex":"%s","cipher":"%s","mac":"%s","hostkey":"%s"},"negotiation_result":"%s","authentication_result":"%s","client_result":"%s","reason":"%s"}' \
            "$idx" "$(json_escape "$desc")" "$(json_escape "$group")" "$(json_escape "$proto")" \
            "$(json_escape "$fk")" "$(json_escape "$fc")" "$(json_escape "$fm")" "$(json_escape "$fh")" \
            "$(json_escape "$nk")" "$(json_escape "$nc")" "$(json_escape "$nm")" "$(json_escape "$nh")" \
            "$(json_escape "$nr")" "$(json_escape "$ar")" "$(json_escape "$cr")" "$(json_escape "$reason")" \
            >> "$JSON_FILE"
    fi
}

should_run() {
    local idx="$1"
    local desc="$2"

    [[ -z "$ONLY_FILTER" ]] && return 0

    if [[ "$ONLY_FILTER" =~ ^[0-9]+$ ]]; then
        [[ "$idx" == "$ONLY_FILTER" ]]
        return
    fi

    shopt -s nocasematch
    [[ "$desc" == *"$ONLY_FILTER"* ]]
    local r=$?
    shopt -u nocasematch
    return "$r"
}

service_restart() {
    if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
        systemctl restart "$SERVICE" >/dev/null 2>&1
        return $?
    fi

    if command -v service >/dev/null 2>&1 && [[ "$SERVICE" != "unknown" ]]; then
        service "$SERVICE" restart >/dev/null 2>&1
        return $?
    fi

    return 1
}

wait_service_ready() {
    # 部分算法（如 8192-bit DH group18-sha512）sshd 启动会明显变慢，
    # 固定 sleep 3 秒可能造成误判为"启动失败"。这里改成最多等 60 秒的
    # 轮询；systemd 环境下如果服务触发了 start-limit-hit（短时间内重启
    # 次数过多被熔断），主动 reset-failed 后重试一次而不是干等到超时。
    local max_wait=60
    local i
    local retried=false
    for i in $(seq 1 "$max_wait"); do
        if service_is_up; then
            return 0
        fi
        if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]] && ! $retried; then
            if systemctl is-failed --quiet "$SERVICE" 2>/dev/null; then
                retried=true
                systemctl reset-failed "$SERVICE" >/dev/null 2>&1 || true
                service_restart >/dev/null 2>&1 || true
            fi
        fi
        sleep 1
    done
    service_is_up
}

service_is_up() {
    if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
        systemctl is-active --quiet "$SERVICE"
        return $?
    fi

    if command -v service >/dev/null 2>&1 && [[ "$SERVICE" != "unknown" ]]; then
        service "$SERVICE" status >/dev/null 2>&1
        return $?
    fi

    return 1
}

detect_log_file() {
    if [[ -f /var/log/secure ]]; then
        printf '%s\n' /var/log/secure
        return
    fi
    if [[ -f /var/log/auth.log ]]; then
        printf '%s\n' /var/log/auth.log
        return
    fi
    printf '%s\n' ""
}

read_log_delta() {
    local file="$1" size="$2"
    [[ -f "$file" ]] || return 0
    local cur
    cur="$(stat -c %s "$file" 2>/dev/null || echo 0)"
    if (( cur >= size )); then
        tail -c +"$((size + 1))" "$file" 2>/dev/null || true
    else
        cat "$file" 2>/dev/null || true
    fi
}

# 使用 sshd -Q 做“支持性预检”。预检只决定 SKIP，不决定 PASS/FAIL。
# sshd -Q 不可用时返回 2，让 sshd -t 作为最终配置校验兜底。
SUPPORTED_KEX=""
SUPPORTED_CIPHER=""
SUPPORTED_MAC=""
SUPPORTED_HOSTKEY=""
load_supported_algorithms() {
    SUPPORTED_KEX="$(sshd -Q kex 2>/dev/null || true)"
    SUPPORTED_CIPHER="$(sshd -Q cipher 2>/dev/null || true)"
    SUPPORTED_MAC="$(sshd -Q mac 2>/dev/null || true)"
    SUPPORTED_HOSTKEY="$(sshd -Q key 2>/dev/null || true)"
    env_log "sshd -Q kex: $([[ -n "$SUPPORTED_KEX" ]] && echo available || echo unavailable)"
    env_log "sshd -Q cipher: $([[ -n "$SUPPORTED_CIPHER" ]] && echo available || echo unavailable)"
    env_log "sshd -Q mac: $([[ -n "$SUPPORTED_MAC" ]] && echo available || echo unavailable)"
    env_log "sshd -Q key: $([[ -n "$SUPPORTED_HOSTKEY" ]] && echo available || echo unavailable)"
}

algo_supported() {
    local type="$1" algo="$2" list=""
    [[ -n "$algo" ]] || return 0
    case "$type" in
        kex) list="$SUPPORTED_KEX" ;;
        cipher) list="$SUPPORTED_CIPHER" ;;
        mac) list="$SUPPORTED_MAC" ;;
        key) list="$SUPPORTED_HOSTKEY" ;;
        *) return 0 ;;
    esac
    [[ -z "$list" ]] && return 2
    if printf '%s\n' "$list" | grep -qxF "$algo"; then
        return 0
    fi
    if [[ "$type" == "key" ]]; then
        case "$algo" in
            rsa-sha2-512|rsa-sha2-256|ssh-rsa)
                if printf '%s\n' "$list" | grep -Eq '^(ssh-rsa|rsa-sha2-256|rsa-sha2-512)$'; then
                    return 0
                fi
                ;;
            ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521)
                if printf '%s\n' "$list" | grep -qxF "$algo"; then return 0; fi
                ;;
        esac
    fi
    return 1
}

make_test_config_from_backup() {
    local proto="$1" idx="$2" desc="$3" kex="$4" cipher="$5" mac="$6" hostkey="$7" ssh1cipher="$8"
    local tmp
    tmp="$(mktemp "${SSHD_CONFIG}.XXXXXX")" || return 1

    # 覆盖块放在原配置最前面。OpenSSH 对同一全局选项通常采用首次获得的值，
    # 这样 /etc/ssh/sshd_config.d/*.conf 中已有算法设置不会抢先生效。
    {
        printf '%s\n' '# ALGO_TEST_ACTIVE_MARKER_DO_NOT_EDIT'
        printf '%s\n' "# 测试项: [#${idx}] ${desc}"
        printf '%s\n' "Port ${PORT}"
        printf '%s\n' 'ListenAddress 127.0.0.1'
        if [[ "$proto" == "1" ]]; then
            printf '%s\n' \
                'Protocol 1' \
                'PermitRootLogin yes' \
                'PasswordAuthentication yes' \
                'UsePAM yes' \
                "Cipher ${ssh1cipher}" \
                'HostKey /etc/ssh/ssh_host_rsa_key' \
                'LogLevel DEBUG3'
        else
            printf '%s\n' \
                'Protocol 2' \
                'PermitRootLogin yes' \
                'PasswordAuthentication yes' \
                'PubkeyAuthentication yes' \
                'UsePAM yes' \
                "KexAlgorithms ${kex}" \
                "Ciphers ${cipher}" \
                "MACs ${mac}" \
                "HostKeyAlgorithms ${hostkey}" \
                'LogLevel DEBUG3'
            case "$hostkey" in
                ssh-dss) printf '%s\n' 'HostKey /etc/ssh/ssh_host_dsa_key' ;;
                ssh-ed25519) printf '%s\n' 'HostKey /etc/ssh/ssh_host_ed25519_key' ;;
                ecdsa-*) printf '%s\n' 'HostKey /etc/ssh/ssh_host_ecdsa_key' ;;
                *) printf '%s\n' 'HostKey /etc/ssh/ssh_host_rsa_key' ;;
            esac
        fi
        printf '%s\n' '# --- END UNIFIED TEST OVERRIDES ---'
    } > "$tmp"

    # 原配置全部保留；仅注释全局范围内与本次测试直接冲突的指令。
    awk '
        BEGIN { in_match=0 }
        /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh][[:space:]]+[Aa][Ll][Ll]([[:space:]]|$)/ { in_match=0; next }
        /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh]([[:space:]]|$)/ { in_match=1 }
        {
            if (!in_match && $0 ~ /^[[:space:]]*(Port|ListenAddress|Protocol|KexAlgorithms|Ciphers|MACs|HostKeyAlgorithms|HostKey|PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|UsePAM|LogLevel)[[:space:]]+/) {
                print "# UNIFIED_TEST_COMMENTED: " $0
            } else {
                print
            }
        }
    ' "$BACKUP_FILE" >> "$tmp" || { rm -f "$tmp"; return 1; }

    chmod 600 "$tmp"
    printf '%s\n' "$tmp"
}

detect_match_algorithm_overrides() {
    local found=""
    found="$(awk '
        BEGIN { in_match=0 }
        /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh][[:space:]]+[Aa][Ll][Ll]([[:space:]]|$)/ { in_match=0; next }
        /^[[:space:]]*[Mm][Aa][Tt][Cc][Hh]([[:space:]]|$)/ { in_match=1; next }
        in_match && $0 ~ /^[[:space:]]*(KexAlgorithms|Ciphers|MACs|HostKeyAlgorithms|HostKey|Cipher|Protocol)[[:space:]]+/ {
            print NR ":" $0
        }
    ' "$BACKUP_FILE" 2>/dev/null || true)"

    if [[ -n "$found" ]]; then
        env_log "WARNING：原始 sshd_config 的 Match 块包含算法/协议覆盖项；测试覆盖已置于 Match 之前，但以下规则已记录："
        while IFS= read -r line; do
            [[ -n "$line" ]] && env_log "  MATCH_OVERRIDE: $line"
        done <<< "$found"
    else
        env_log "Match 算法覆盖检查：未发现 Match 块中的 Kex/Cipher/MAC/HostKey/Protocol 指令"
    fi
}

make_ssh2_config() {
    local idx="$1" desc="$2" kex="$3" cipher="$4" mac="$5" hostkey="$6"

    local cfg
    cfg=$(make_test_config_from_backup 2 "$idx" "$desc" "$kex" "$cipher" "$mac" "$hostkey" "")

    cat "$cfg"
    rm -f "$cfg"
}

make_ssh1_config() {
    local idx="$1" desc="$2" cipher="$3"

    local cfg
    cfg=$(make_test_config_from_backup 1 "$idx" "$desc" "" "" "" "" "$cipher")

    cat "$cfg"
    rm -f "$cfg"
}

detect_match_algorithm_overrides

run_auto_ssh2() {
    local kex="$1" cipher="$2" mac="$3" hostkey="$4" output="$5"

    ssh -vvv \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=20 \
        -o ConnectionAttempts=1 \
        -o BatchMode=yes \
        -o PreferredAuthentications=publickey \
        -o IdentitiesOnly=yes \
        -i "$AUTO_KEY" \
        -o KexAlgorithms="$kex" \
        -o Ciphers="$cipher" \
        -o MACs="$mac" \
        -o HostKeyAlgorithms="$hostkey" \
        -p "$PORT" "$LOOPBACK_TARGET" true \
        >"$output" 2>&1
}

run_auto_ssh1() {
    local cipher="$1" output="$2"

    ssh -vvv -1 \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=20 \
        -o ConnectionAttempts=1 \
        -o BatchMode=yes \
        -o PreferredAuthentications=password \
        -p "$PORT" \
        -c "$cipher" \
        "$LOOPBACK_TARGET" true \
        >"$output" 2>&1
}

# 环境准备完成后再读取 sshd 实际支持列表；不可用时由 sshd -t 兜底。
load_supported_algorithms
{
    echo "----- Environment Algorithm Prediction -----"
    echo "[KEX]"; printf '%s\n' "$SUPPORTED_KEX"
    echo "[CIPHER]"; printf '%s\n' "$SUPPORTED_CIPHER"
    echo "[MAC]"; printf '%s\n' "$SUPPORTED_MAC"
    echo "[HOSTKEY]"; printf '%s\n' "$SUPPORTED_HOSTKEY"
    echo "---------------------------------------------"
} >> "$ENV_FILE"

restore_after_test() {
    local reason="${1:-测试项结束恢复}"
    local restore_tmp=""

    if [[ -f "$BACKUP_FILE" ]]; then
        restore_tmp="$(mktemp "${SSHD_CONFIG}.restore.XXXXXX" 2>/dev/null || true)"
        if [[ -n "$restore_tmp" ]] && cp -a "$BACKUP_FILE" "$restore_tmp" && mv -f "$restore_tmp" "$SSHD_CONFIG"; then
            log "[恢复] $reason：sshd_config 已恢复"
        else
            log "[恢复] ERROR：$reason：sshd_config 恢复失败"
            [[ -n "$restore_tmp" ]] && rm -f "$restore_tmp"
        fi
    fi

    if $INITIAL_SERVICE_KNOWN; then
        if $INITIAL_SERVICE_ACTIVE; then
            service_restart >/dev/null 2>&1 || log "[恢复] WARNING：$reason：sshd 无法恢复为运行状态"
        else
            if [[ "$INIT" == "systemd" && "$SERVICE" != "unknown" ]]; then
                systemctl stop "$SERVICE" >/dev/null 2>&1 || true
            elif command -v service >/dev/null 2>&1 && [[ "$SERVICE" != "unknown" ]]; then
                service "$SERVICE" stop >/dev/null 2>&1 || true
            fi
        fi
    fi

    rm -f /tmp/algo_client.* /tmp/algo_sshd_t.*
}

record_result() {
    local idx="$1" desc="$2" group="$3" proto="$4"
    local fk="$5" fc="$6" fm="$7" fh="$8"
    local nk="$9" nc="${10}" nm="${11}" nh="${12}"
    local nr="${13}" ar="${14}" cr="${15}" reason="${16}"

    case "${nr}/${ar}/${cr}" in
        PASS/PASS/*) PASS=$((PASS + 1)) ;;
        PASS/FAIL/*|FAIL/*/*) FAIL=$((FAIL + 1)) ;;
        SKIP/*/*|*/*/CLIENT_REJECTED) SKIP=$((SKIP + 1)) ;;
        *) UNKNOWN=$((UNKNOWN + 1)) ;;
    esac

    write_result "$idx" "$desc" "$group" "$proto" \
        "$fk" "$fc" "$fm" "$fh" "$nk" "$nc" "$nm" "$nh" \
        "$nr" "$ar" "$cr" "$reason"
}

test_one() {
    local idx="$1"
    local p=$((idx - 1))

    local desc="${DESCS[$p]}"
    local kex="${KEXES[$p]}"
    local cipher="${CIPHERS[$p]}"
    local mac="${MACS[$p]}"
    local hostkey="${HOSTKEYS[$p]}"
    local group="${TEST_GROUPS[$p]}"
    local proto="${PROTOCOLS[$p]}"

    should_run "$idx" "$desc" || return 0

    RUN_INDEX=$((RUN_INDEX + 1))

    local tmp=""
    local client_out=""
    local server_log=""
    local log_before=0
    local server_delta=""
    local reason=""
    local rc=0

    local NK=""
    local NC=""
    local NM=""
    local NH=""

    local NR="UNKNOWN"
    local AR="UNKNOWN"
    local CR="UNKNOWN"

    log ""
    log "============================================================"
    log "[协商测试] #${idx} ${desc}"
    log "固定：CIPHER：${cipher}"
    log "测试：KEX：${kex} HOST_KEY：${hostkey} MAC：${mac}"

    # 客户端完全不支持 SSH-1 时，不进入 SSH-1 协商测试；这属于客户端能力限制，不能判为服务端算法 FAIL。
    if [[ "$proto" == "1" && ! "$SSH_VER" =~ ^5\. ]]; then
        NR="UNKNOWN"
        AR="NOT_TESTED"
        CR="CLIENT_REJECTED"
        reason="当前 OpenSSH 客户端版本不支持 SSH-1；按原脚本要求仅在 CentOS 6/OpenSSH 5.x 环境测试"
        record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
            "" "" "" "" "$NR" "$AR" "$CR" "$reason"
        log "协商结果：UNKNOWN；认证结果：NOT_TESTED；客户端结果：CLIENT_REJECTED"
        return 0
    fi

    # sshd -Q 明确表示不支持时直接 SKIP；查询不可用则交给 sshd -t 兜底。
    local unsupported="" qrc
    if [[ "$proto" == "2" ]]; then
        algo_supported kex "$kex"; qrc=$?; [[ $qrc -eq 1 ]] && unsupported+=" KEX[$kex]"
        algo_supported cipher "$cipher"; qrc=$?; [[ $qrc -eq 1 ]] && unsupported+=" CIPHER[$cipher]"
        algo_supported mac "$mac"; qrc=$?; [[ $qrc -eq 1 ]] && unsupported+=" MAC[$mac]"
        algo_supported key "$hostkey"; qrc=$?; [[ $qrc -eq 1 ]] && unsupported+=" HOSTKEY[$hostkey]"
        if [[ -n "$unsupported" ]]; then
            record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
                "" "" "" "" "SKIP" "NOT_TESTED" "NOT_APPLICABLE" "sshd -Q 明确不支持:$unsupported"
            log "SKIP [#$idx] $desc — sshd -Q 明确不支持:$unsupported"
            return 0
        fi
    fi

    # CentOS 6 的 DSA 测试只有真正存在 DSA host key 时才执行。
    if [[ "$hostkey" == "ssh-dss" && ! -f /etc/ssh/ssh_host_dsa_key ]]; then
        record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
            "" "" "" "" "SKIP" "NOT_TESTED" "NOT_APPLICABLE" "缺少 /etc/ssh/ssh_host_dsa_key"
        log "SKIP [#$idx] $desc — 缺少 DSA host key"
        return 0
    fi

    # CentOS 6 SSH-1 使用原脚本的 Protocol 1 配置；SSH-2 使用统一配置。
    if [[ "$proto" == "1" ]]; then
        tmp="$(mktemp "${SSHD_CONFIG}.XXXXXX")"
        make_ssh1_config "$idx" "$desc" "$cipher" > "$tmp"
    else
        tmp="$(mktemp "${SSHD_CONFIG}.XXXXXX")"
        make_ssh2_config "$idx" "$desc" "$kex" "$cipher" "$mac" "$hostkey" > "$tmp"
    fi
    chmod 600 "$tmp"

    local syntax_err
    syntax_err="$(mktemp /tmp/algo_sshd_t.XXXXXX)"

    if ! sshd -t -f "$tmp" >"$syntax_err" 2>&1; then
        reason="$(head -3 "$syntax_err" | tr '\n' ' ')"
        rm -f "$syntax_err" "$tmp"

        NR="SKIP"
        AR="NOT_TESTED"
        CR="SERVER_CONFIG_REJECTED"

        log "实际协商：UNKNOWN"
        log "协商结果：SKIP"
        log "认证结果：NOT_TESTED"
        log "原因：sshd -t 配置校验失败：$reason"

        record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
            "$NK" "$NC" "$NM" "$NH" "$NR" "$AR" "$CR" "$reason"
        return 0
    fi
    rm -f "$syntax_err"

    mv -f "$tmp" "$SSHD_CONFIG"

    if ! service_restart; then
        NR="UNKNOWN"
        AR="NOT_TESTED"
        CR="SERVER_RESTART_FAILED"
        reason="sshd 重启失败"

        log "实际协商：UNKNOWN"
        log "协商结果：UNKNOWN"
        log "认证结果：NOT_TESTED"
        log "原因：$reason"

        record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
            "$NK" "$NC" "$NM" "$NH" "$NR" "$AR" "$CR" "$reason"
        rm -f "$tmp"
        restore_after_test "sshd 重启失败"
        return 0
    fi

    if ! wait_service_ready; then
        NR="UNKNOWN"
        AR="NOT_TESTED"
        CR="SERVER_DOWN"
        reason="sshd 重启后 60 秒内未进入运行状态"

        log "实际协商：UNKNOWN"
        log "协商结果：UNKNOWN"
        log "认证结果：NOT_TESTED"
        log "原因：$reason"

        record_result "$idx" "$desc" "$group" "$proto" "$kex" "$cipher" "$mac" "$hostkey" \
            "$NK" "$NC" "$NM" "$NH" "$NR" "$AR" "$CR" "$reason"
        rm -f "$client_out" "$tmp"
        restore_after_test "sshd 启动后异常"
        return 0
    fi

    server_log="$(detect_log_file)"
    if [[ -n "$server_log" ]]; then
        log_before="$(stat -c %s "$server_log" 2>/dev/null || echo 0)"
    fi

    client_out="$(mktemp /tmp/algo_client.XXXXXX)"

    if $AUTO; then
        env_log "自动认证：root@127.0.0.1，临时公钥 marker=${AUTO_MARKER}"
        if [[ "$proto" == "1" ]]; then
            run_auto_ssh1 "$cipher" "$client_out"
            rc=$?
        else
            run_auto_ssh2 "$kex" "$cipher" "$mac" "$hostkey" "$client_out"
            rc=$?
        fi
    else
        log "手动模式：请使用原脚本的手动触发方式发起本次连接。"
        log "连接完成后按 Enter 继续读取测试结果。"
        read -r
        rc=0
    fi

    sleep 1

    if [[ -n "$server_log" ]]; then
        server_delta="$(read_log_delta "$server_log" "$log_before")"
    fi

    # --------------------------------------------------------
    # 自动模式：优先从 ssh -vvv 得到实际协商参数。
    # 这比用 ssh 退出码判断算法结果准确。
    # --------------------------------------------------------
    if [[ "$proto" == "2" && -s "$client_out" ]]; then
        NK="$(grep -m1 -E 'kex: algorithm: ' "$client_out" |
            sed 's/.*kex: algorithm: //' | tr -d '\r')"
        NH="$(grep -m1 -E 'kex: host key algorithm: ' "$client_out" |
            sed 's/.*kex: host key algorithm: //' | tr -d '\r')"
        NC="$(grep -m1 -E 'server->client cipher: ' "$client_out" |
            sed 's/.*server->client cipher: //' | cut -d, -f1 | tr -d '\r')"
        NM="$(grep -m1 -E 'server->client MAC: ' "$client_out" |
            sed 's/.*server->client MAC: //' | cut -d, -f1 | tr -d '\r')"
    fi

    # --------------------------------------------------------
    # 客户端明确拒绝算法：不把客户端不支持误判成服务端 FAIL。
    # --------------------------------------------------------
    if grep -qiE \
        'unknown cipher|Bad SSH2 cipher|Bad SSH2 KEX|Bad SSH2 MAC|unknown option|Unsupported option|no matching' \
        "$client_out" 2>/dev/null; then

        if [[ -z "$NK$NC$NM$NH" ]]; then
            NR="UNKNOWN"
            AR="NOT_TESTED"
            CR="CLIENT_REJECTED"
            reason="$(grep -iE \
                'unknown cipher|Bad SSH2 cipher|Bad SSH2 KEX|Bad SSH2 MAC|unknown option|Unsupported option|no matching' \
                "$client_out" | tail -1)"
        fi
    fi

    # --------------------------------------------------------
    # 协商判断
    # --------------------------------------------------------
    if [[ "$NR" == "UNKNOWN" && "$CR" != "CLIENT_REJECTED" ]]; then
        if grep -qiE \
            'Unable to negotiate|no matching .*found|no matching .*method|kex_exchange_identification' \
            "$client_out" "$server_log" 2>/dev/null; then

            NR="FAIL"
            AR="NOT_TESTED"
            CR="NEGOTIATION_FAIL"
            reason="$(grep -hiE \
                'Unable to negotiate|no matching .*found|no matching .*method|kex_exchange_identification' \
                "$client_out" "$server_log" 2>/dev/null | tail -1)"

        elif [[ -n "$NK$NC$NM$NH" ]]; then
            if [[ "$NK" == "$kex" && "$NC" == "$cipher" && "$NM" == "$mac" && "$NH" == "$hostkey" ]]; then
                NR="PASS"
            else
                NR="FAIL"
                AR="NOT_TESTED"
                CR="NEGOTIATION_MISMATCH"
                reason="客户端 DEBUG3 检测到的实际协商算法与本次固定测试组合不一致"
            fi
        fi
    fi

    # --------------------------------------------------------
    # 认证判断
    # 认证结果独立于协商结果。
    # --------------------------------------------------------
    if [[ "$NR" == "PASS" ]]; then
        # 客户端 DEBUG3 明确出现认证成功时优先采用客户端证据。
        if grep -qiE 'Authenticated to .*|Authentication succeeded' "$client_out" 2>/dev/null; then
            AR="PASS"
            CR="PASS"

        elif grep -qiE \
            'Accepted password|Accepted publickey|Accepted keyboard-interactive|User .* authenticated|authentication success' \
            "$server_delta" "$client_out" 2>/dev/null; then

            AR="PASS"
            CR="PASS"

        elif grep -qiE \
            'No more authentication methods to try|Permission denied|Failed password|Failed publickey|Failed none|authentication failure' \
            "$client_out" "$server_delta" 2>/dev/null; then

            AR="FAIL"
            CR="PASS"

        else
            # 协商已经从客户端 DEBUG3 明确得到实际算法，但认证日志没有
            # 足够证据时不能擅自判 PASS/FAIL。
            AR="UNKNOWN"
            CR="NEGOTIATED"
            reason="${reason:-协商已成功，但没有足够日志准确判断认证结果}"
        fi
    fi

    # SSH-1 的服务端日志是主要判断依据；现代 SSH 客户端可能自身已移除 SSH-1。
    if [[ "$proto" == "1" ]]; then
        if grep -qiE 'Unable to negotiate|no matching|Connection closed|Did not receive identification' \
            "$server_delta" "$client_out" 2>/dev/null; then
            NR="FAIL"
            AR="NOT_TESTED"
            CR="NEGOTIATION_FAIL"
            reason="$(grep -hiE \
                'Unable to negotiate|no matching|Connection closed|Did not receive identification' \
                "$server_delta" "$client_out" 2>/dev/null | tail -1)"
        elif grep -qiE 'Accepted|authentication success|User .* authenticated' \
            "$server_delta" "$client_out" 2>/dev/null; then
            NR="PASS"
            AR="PASS"
            CR="PASS"
        elif grep -qiE 'Failed password|Failed publickey|Failed none|authentication failure' \
            "$server_delta" "$client_out" 2>/dev/null; then
            NR="PASS"
            AR="FAIL"
            CR="PASS"
        elif grep -qiE 'unknown option|Unsupported|Protocol major versions differ|SSH protocol version 1' \
            "$client_out" 2>/dev/null; then
            NR="UNKNOWN"
            AR="NOT_TESTED"
            CR="CLIENT_REJECTED"
            reason="$(grep -iE \
                'unknown option|Unsupported|Protocol major versions differ|SSH protocol version 1' \
                "$client_out" | tail -1)"
        else
            NR="UNKNOWN"
            AR="UNKNOWN"
            CR=$([[ "$rc" -eq 0 ]] && echo "UNKNOWN" || echo "CLIENT_EXIT_${rc}")
            reason="${reason:-SSH-1 未找到足以证明协商/认证结果的日志}"
        fi
    fi

    # --------------------------------------------------------
    # 手动模式实际协商参数
    #
    # 原 4 脚本的手动模式不是由本脚本启动客户端，因此不能伪造
    # “实际协商”字段。若服务端 DEBUG3 日志能明确给出算法则记录，
    # 否则记录 UNKNOWN。
    # --------------------------------------------------------
    if ! $AUTO && [[ "$proto" == "2" ]]; then
        if [[ -z "$NK" ]]; then
            NK="$(printf '%s\n' "$server_delta" |
                grep -m1 -E 'kex: algorithm: ' |
                sed 's/.*kex: algorithm: //' | tr -d '\r')"
        fi
        if [[ -z "$NH" ]]; then
            NH="$(printf '%s\n' "$server_delta" |
                grep -m1 -E 'kex: host key algorithm: ' |
                sed 's/.*kex: host key algorithm: //' | tr -d '\r')"
        fi
        if [[ -z "$NC" ]]; then
            NC="$(printf '%s\n' "$server_delta" |
                grep -m1 -E 'server->client cipher: ' |
                sed 's/.*server->client cipher: //' | cut -d, -f1 | tr -d '\r')"
        fi
        if [[ -z "$NM" ]]; then
            NM="$(printf '%s\n' "$server_delta" |
                grep -m1 -E 'server->client MAC: ' |
                sed 's/.*server->client MAC: //' | cut -d, -f1 | tr -d '\r')"
        fi
    fi

    if [[ "$NR" == "PASS" && "$AR" == "UNKNOWN" && -z "$reason" ]]; then
        reason="协商成功；认证状态无法从当前日志准确确定"
    fi

    if [[ -z "$reason" ]]; then
        reason=""
    fi

    log "实际协商：KEX=${NK:-UNKNOWN} CIPHER=${NC:-UNKNOWN} MAC=${NM:-UNKNOWN} HOST_KEY=${NH:-UNKNOWN}"
    log "协商结果：${NR}"
    log "认证结果：${AR}"
    log "客户端结果：${CR}"
    [[ -n "$reason" ]] && log "原因：${reason}"

    # 计数只反映最终分类，不与 ssh 命令退出码直接绑定。
    record_result "$idx" "$desc" "$group" "$proto" \
        "$kex" "$cipher" "$mac" "$hostkey" \
        "$NK" "$NC" "$NM" "$NH" \
        "$NR" "$AR" "$CR" "$reason"

    rm -f "$client_out" "$tmp"
    restore_after_test "测试项 #${idx} 完成"
}

log "============================================================"
log "SSH 算法协商统一测试"
log "系统：$OS_PRETTY"
log "OpenSSH：${SSH_VERSION_STR:-unknown}"
log "Profile：$PROFILE"
log "模式：$($AUTO && echo 自动 || echo 手动)"
log "端口：$PORT"
log "测试项：$TEST_INDEX"
log "结果格式：$RESULT_FORMAT"
log "============================================================"

env_log "配置备份: $BACKUP_FILE"
env_log "测试项总数: $TEST_INDEX"
env_log "初始服务状态: $($INITIAL_SERVICE_ACTIVE && echo running || echo stopped/unknown)"
env_log "初始 crypto-policy: ${INITIAL_CRYPTO_POLICY:-未检测到}"

for ((i=1; i<=TEST_INDEX; i++)); do
    test_one "$i"
done

if [[ "$RESULT_FORMAT" == "json" ]]; then
    printf '\n]\n' >> "$JSON_FILE"
fi

env_log "结束时间: $(date '+%Y-%m-%d %H:%M:%S %Z')"
env_log "PASS: $PASS"
env_log "FAIL: $FAIL"
env_log "UNKNOWN: $UNKNOWN"
env_log "SKIP: $SKIP"
env_log "配置恢复要求: 已注册 EXIT/INT/TERM cleanup"

log ""
log "============================================================"
log "测试完成"
log "PASS: $PASS"
log "FAIL: $FAIL"
log "UNKNOWN: $UNKNOWN"
log "SKIP: $SKIP"
log "总测试项: $TEST_INDEX"

if [[ "$RESULT_FORMAT" == "csv" ]]; then
    log "结果文件：$CSV_FILE"
else
    log "结果文件：$JSON_FILE"
fi

log "详细测试日志：$LOG_FILE"
log "环境/执行信息：$ENV_FILE"
log "============================================================"

exit 0