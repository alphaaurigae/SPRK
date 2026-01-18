#!/usr/bin/env bash

set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/bash/shared/default.sh"


SERVER_BIN="$SCRIPT_DIR/server.sh"
CLIENT_BIN="$SCRIPT_DIR/client.sh"

IP="127.0.0.1"
PORT="1566"

SESSION_ID="nHkrMugYTkqiQzZxUDq6wzb5NMXPbRv7gBjHmaUCyLFR21onNu9KWwL3CYMK"

KEY_RON_PEM="$SCRIPT_DIR/sample/ron.sk.pem"
CERT_RON="$SCRIPT_DIR/sample/ron.crt"

KEY_BETH_PEM="$SCRIPT_DIR/sample/beth.sk.pem"
CERT_BETH="$SCRIPT_DIR/sample/beth.crt"

KEY_BOB_PEM="$SCRIPT_DIR/sample/bob.sk.pem"
CERT_BOB="$SCRIPT_DIR/sample/bob.crt"

# !important DO NOT CHANGE!
FP_BETH_FROM_RON=""
FP_RON_FROM_BETH=""
FP_BOB_FROM_RON=""
FP_BOB_FROM_BETH=""
FP_RON_FROM_BOB=""
FP_BETH_FROM_BOB=""
#

TMUX_SESSION="sprk_test_$$"

# ERROR PRONE IF SHORT
DELAY_SERVER_START="1"
DELAY_SERVER_SHUTDOWN="0.3"
DELAY_USER_CONNECT_INIT="0.3"
DELAY_USER_CONNECT_EST="0.3"
DELAY_USER_HELLO_MSG="0.3"
DELAY_USER_LISTUSER="0.3"
DELAY_USER_SHOW_PUBK="0.3"
DELAY_USER_HELP="0.3"
DELAY_USER_GRP="0.3"
DELAY_USER_QUIT="0.3"
DELAY_TMUX_SHUTDOWN="0.3"

PASSED_CHECKS=()
HAS_FAILED="false"
FAILED_DESC=""
FAILED_PATTERN=""
FAILED_OUTPUT=""
FAILED_TARGET=""


declare -A CLIENT_EXPECTED_EXIT
CLIENT_EXPECTED_EXIT[bob]=true
log() { echo "[$(date +%H:%M:%S)] $*"; }

send_cmd() {
    local target=$1
    local cmd=$2
    local desc=${3:-""}
    printf "%s%s%s%s\n" "${BOLD}${WHITE}" "STATUS:" "${RESET}" " >>> Sending to $target: '$cmd' $desc" >&2
    tmux send-keys -t "$TMUX_SESSION:$target" "$cmd" C-m
}


check_output() {
    local target=$1
    local pattern=$2
    local desc=$3
    local timeout=${4:-2}
    local waited=0
    local grace_period=3

    printf "%s\n" "DEBUG: check_output target=${target} pattern=${pattern} timeout=${timeout} grace=${grace_period}" >&2

    while (( waited < timeout )); do
        if (( waited >= grace_period )); then
                        if ! tmux list-windows -t "$TMUX_SESSION" 2>/dev/null | grep -qE "^[0-9]+: $target([*[:space:]]|$)"; then

                HAS_FAILED=true
                FAILED_DESC="Client $target crashed during check: $desc"
                FAILED_TARGET="$target"
                FAILED_OUTPUT="tmux window gone"
                FAILED_PATTERN="$pattern"

                printf "\n%s%s%s%s\n" "${BOLD}${BRIGHT_RED}" "CRASH DETECTED:" "${RESET}" " Client died while waiting for output" >&2
                print_final_failure_banner
                exit 1
            fi
        fi

        local output
        output=$(tmux capture-pane -p -S -3000 -t "$TMUX_SESSION:$target" 2>/dev/null || echo "ERROR: capture failed")

        if [[ "$output" =~ (no\ server|failed|error|dead) && waited -ge grace_period ]]; then
            HAS_FAILED=true
            FAILED_DESC="Client $target inaccessible during check: $desc"
            FAILED_TARGET="$target"
            FAILED_OUTPUT="$output"
            print_final_failure_banner
            exit 1
        fi

        local output_normalized
        output_normalized=$(echo "$output" | tr -d '\n\r' | tr -s ' ')

        if echo "$output_normalized" | grep -qE "$pattern"; then
            printf "%s%s%s%s\n" "${BOLD}${BRIGHT_GREEN}" "PASS:" "${RESET}" " $desc" >&2
            PASSED_CHECKS+=("$desc")
            return 0
        fi

        if echo "$output" | grep -qE "$pattern"; then
            printf "%s%s%s%s\n" "${BOLD}${BRIGHT_GREEN}" "PASS:" "${RESET}" " $desc" >&2
            PASSED_CHECKS+=("$desc")
            return 0
        fi

        sleep 1
        ((waited++))
    done

    HAS_FAILED=true
    FAILED_DESC="$desc"
    FAILED_PATTERN="$pattern"
    FAILED_OUTPUT="$output"
    FAILED_TARGET="$target"

    printf "%s%s%s%s\n" "${BOLD}${BRIGHT_RED}" "FAIL:" "${RESET}" " $desc (timeout ${timeout}s)" >&2
    printf "%s%s%s%s\n" "${BOLD}${WHITE}" "Expected pattern:" "${RESET}" " $pattern" >&2
    printf "%s%s%s%s\n" "${BOLD}${WHITE}" "Last output from $target:" "${RESET}" >&2
    printf "%s%s%s\n" "${BOLD}${WHITE}" "$output" "${RESET}" >&2

    print_final_failure_banner
    exit 1
}

extract_fps_from_client() {
    local client=$1
    local desc=$2
    printf "%s%s%s%s\n" "${BOLD}${WHITE}" "STATUS:" "${RESET}" " Extracting FPs from $client ($desc)" >&2

    send_cmd "$client" "list users" "(extract FPs)"
    sleep $DELAY_SERVER_START

    local output
    output=$(tmux capture-pane -p -t "$TMUX_SESSION:$client" 2>/dev/null)

    local ron_fp=$(echo "$output" | grep -oE "ron \[([a-f0-9]{64})\]" | grep -oE "[a-f0-9]{64}" | head -1)
    local beth_fp=$(echo "$output" | grep -oE "beth \[([a-f0-9]{64})\]" | grep -oE "[a-f0-9]{64}" | head -1)
    local bob_fp=$(echo "$output" | grep -oE "bob \[([a-f0-9]{64})\]" | grep -oE "[a-f0-9]{64}" | head -1)

    case "$client" in
        ron)
            [[ -n "$beth_fp" ]] && FP_BETH_FROM_RON="$beth_fp"
            [[ -n "$bob_fp" ]] && FP_BOB_FROM_RON="$bob_fp"
            ;;
        beth)
            [[ -n "$ron_fp" ]] && FP_RON_FROM_BETH="$ron_fp"
            [[ -n "$bob_fp" ]] && FP_BOB_FROM_BETH="$bob_fp"
            ;;
        bob)
            [[ -n "$ron_fp" ]] && FP_RON_FROM_BOB="$ron_fp"
            [[ -n "$beth_fp" ]] && FP_BETH_FROM_BOB="$beth_fp"
            ;;
    esac

    printf "%s%s%s\n" "${BOLD}${WHITE}" "Updated FPs after $client list" "${RESET}" >&2
    printf "%s%s%s\n" "${WHITE}" "FP_BETH_FROM_RON = $FP_BETH_FROM_RON" "${RESET}" >&2
    printf "%s%s%s\n" "${WHITE}" "FP_RON_FROM_BETH = $FP_RON_FROM_BETH" "${RESET}" >&2
    printf "%s%s%s\n" "${WHITE}" "FP_BOB_FROM_RON  = $FP_BOB_FROM_RON" "${RESET}" >&2
    printf "%s%s%s\n" "${WHITE}" "FP_BOB_FROM_BETH = $FP_BOB_FROM_BETH" "${RESET}" >&2
    printf "%s%s%s\n" "${WHITE}" "FP_RON_FROM_BOB  = $FP_RON_FROM_BOB" "${RESET}" >&2
    printf "%s%s%s\n" "${WHITE}" "FP_BETH_FROM_BOB = $FP_BETH_FROM_BOB" "${RESET}" >&2
}

cleanup() {
    printf "%s%s%s\n" "${BOLD}${WHITE}" "=== CLEANUP STARTED ===" "${RESET}" >&2
    pkill -f "^${SERVER_BIN} ${PORT}$" || true
    pkill -f "${CLIENT_BIN}.*${PORT}" || true
    tmux kill-session -t "$TMUX_SESSION" 2>/dev/null || true
    printf "%s%s%s\n" "${BOLD}${WHITE}" "=== CLEANUP DONE ===" "${RESET}" >&2
}
check_client_alive() {
    local target=$1
    local desc=${2:-"Client $target is still alive"}

        if ! tmux list-windows -t "$TMUX_SESSION" 2>/dev/null | grep -qE "^[0-9]+: $target([*[:space:]]|$)"; then

        HAS_FAILED=true
        FAILED_DESC="$desc"
        FAILED_PATTERN="tmux window '$target' exists"
        FAILED_OUTPUT="Window '$target' disappeared from session $TMUX_SESSION — client likely crashed"
        FAILED_TARGET="$target"

        printf "\n%s%s%s%s\n" "${BOLD}${BRIGHT_RED}" "CRASH DETECTED:" "${RESET}" " $desc" >&2
        printf "%s%s%s%s\n" "${BOLD}${WHITE}" "Reason:" "${RESET}" " tmux window no longer exists (client terminated unexpectedly)" >&2

        print_final_failure_banner
        exit 1
    fi
}

trap cleanup EXIT INT TERM


Test_001_Client_help() {
    printf "%s%s%s\n" "${BOLD}${WHITE}" "Test 001: Client help" "${RESET}" >&2
    local out=$("$CLIENT_BIN" 2>&1 || true)
    [[ $out == *"Usage: chat_client"* && $out == *"q                         quit"* ]] \
        && printf "%s%s%s%s\n" "${BOLD}${BRIGHT_GREEN}" "SUCCESS:" "${RESET}" " Help complete" >&2 \
        || (printf "%s%s%s%s\n" "${BOLD}${BRIGHT_RED}" "FAIL:" "${RESET}" " Help NOT complete" >&2; return 1)
}


EXEC_002_Start_server() {
    printf "%s%s%s\n" "${BOLD}${WHITE}" "EXEC 002: Start Server" "${RESET}" >&2
    tmux new-session -d -s "$TMUX_SESSION" -c "$SCRIPT_DIR"
    tmux rename-window -t "$TMUX_SESSION:0" server
    send_cmd server "$SERVER_BIN $PORT" "(start server)"
    sleep $DELAY_SERVER_START
    nc -z "$IP" "$PORT" && printf "%s%s%s%s\n" "${BOLD}${BRIGHT_GREEN}" "SUCCESS:" "${RESET}" " Server listening" >&2 \
        || (printf "%s%s%s%s\n" "${BOLD}${BRIGHT_RED}" "FAIL:" "${RESET}" " Server not listening" >&2; return 1)
}


Test_003_Ron_connect() {
    printf "%s%s%s\n" "${BOLD}${WHITE}" "Test 003: Ron connects" "${RESET}" >&2
    tmux new-window -t "$TMUX_SESSION:1" -n ron
    send_cmd ron "$CLIENT_BIN $IP $PORT ron $KEY_RON_PEM $CERT_RON --sessionid $SESSION_ID" "(ron login)"
    sleep $DELAY_USER_CONNECT_INIT
    check_output ron "TLS handshake successful" "Ron connected"
    sleep $DELAY_USER_CONNECT_EST
    check_output server "connect ron session=.*" "Server sees ron"
}


Test_004_Beth_connect() {
    printf "%s%s%s\n" "${BOLD}${WHITE}" "Test 004: Beth connects" "${RESET}" >&2
    tmux new-window -t "$TMUX_SESSION:2" -n beth
    send_cmd beth "$CLIENT_BIN $IP $PORT beth $KEY_BETH_PEM $CERT_BETH --sessionid $SESSION_ID" "(beth login)"
    sleep $DELAY_USER_CONNECT_INIT
    check_output beth "TLS handshake successful" "Beth connected"
    check_output beth "connect ron pubkey=.*" "Beth sees ron" 10
    check_output beth "peer ron ready" "Beth ready with ron" 10
    sleep $DELAY_USER_CONNECT_EST
    check_output server "connect beth session=.*" "Server sees beth"
}


Test_005_Ron_Beth_messaging_and_fp_extraction() {
    printf "%s%s%s\n" "${BOLD}${WHITE}" "Test 005: Ron ↔ Beth messaging + extract FPs" "${RESET}" >&2
    extract_fps_from_client "ron" "after Ron+Beth connected"
    extract_fps_from_client "beth" "from Beth's view"

    [[ -n "$FP_BETH_FROM_RON" && -n "$FP_RON_FROM_BETH" ]] \
        || (printf "%s%s%s%s\n" "${BOLD}${BRIGHT_RED}" "FAIL:" "${RESET}" " Missing required FPs for Ron↔Beth messaging" >&2; return 1)

    send_cmd ron "$FP_BETH_FROM_RON hello beth from ron" "(ron→beth)"
    sleep $DELAY_USER_HELLO_MSG
    check_output beth "\[.*\] \[ron .*] hello beth from ron" "Beth received from ron"

    send_cmd beth "$FP_RON_FROM_BETH hello ron from beth" "(beth→ron)"
    sleep $DELAY_USER_HELLO_MSG
    check_output ron "\[.*\] \[beth .*] hello ron from beth" "Ron received from beth"
}


Test_006_Bob_connect() {
    printf "%s%s%s\n" "${BOLD}${WHITE}" "Test 006: Bob connects + triangular rekey" "${RESET}" >&2
    tmux new-window -t "$TMUX_SESSION:3" -n bob
    send_cmd bob "$CLIENT_BIN $IP $PORT bob $KEY_BOB_PEM $CERT_BOB --sessionid $SESSION_ID" "(bob login)"
    sleep $DELAY_USER_CONNECT_INIT
    check_output bob "TLS handshake successful" "Bob connected"
    check_output bob "connect ron pubkey=.*" "Bob sees ron" 45
    check_output bob "connect beth pubkey=.*" "Bob sees beth" 45
    check_output bob "peer ron ready" "Bob ready with ron" 45
    check_output bob "peer beth ready" "Bob ready with beth" 45
    sleep $DELAY_USER_CONNECT_EST
    check_output server "connect bob session=.*" "Server sees bob"
}


Test_007_Extract_all_fps_after_bob() {
    printf "%s%s%s\n" "${BOLD}${WHITE}" "Test 007: Extract all fingerprints after Bob joined" "${RESET}" >&2
    extract_fps_from_client "ron" "from Ron"
    extract_fps_from_client "beth" "from Beth"
    extract_fps_from_client "bob" "from Bob"

    [[ -n "$FP_BOB_FROM_RON" && -n "$FP_BOB_FROM_BETH" && -n "$FP_RON_FROM_BOB" && -n "$FP_BETH_FROM_BOB" ]] \
        || (printf "%s%s%s%s\n" "${BOLD}${BRIGHT_RED}" "FAIL:" "${RESET}" " Some fingerprints missing after Bob joined" >&2; return 1)
}



Test_008_Triangular_messaging() {
    printf "%s%s%s\n" "${BOLD}${WHITE}" "Test 008: Full triangular messaging" "${RESET}" >&2
    send_cmd ron "$FP_BOB_FROM_RON hi bob from ron" "(ron→bob)"
    sleep $DELAY_USER_HELLO_MSG
    check_output bob "\[.*\] \[ron .*] hi bob from ron" "Bob got from ron"

    send_cmd beth "$FP_BOB_FROM_BETH hi bob from beth" "(beth→bob)"
    sleep $DELAY_USER_HELLO_MSG
    check_output bob "\[.*\] \[beth .*] hi bob from beth" "Bob got from beth"

    send_cmd bob "$FP_RON_FROM_BOB hi ron from bob" "(bob→ron)"
    sleep $DELAY_USER_HELLO_MSG
    check_output ron "\[.*\] \[bob .*] hi ron from bob" "Ron got from bob"

    send_cmd bob "$FP_BETH_FROM_BOB hi beth from bob" "(bob→beth)"
    sleep $DELAY_USER_HELLO_MSG
    check_output beth "\[.*\] \[bob .*] hi beth from bob" "Beth got from bob"

}


Test_009_Multi_recipient() {
    printf "%s%s%s\n" "${BOLD}${WHITE}" "Test 009: Multi-recipient messaging" "${RESET}" >&2
    send_cmd ron "$FP_BETH_FROM_RON,$FP_BOB_FROM_RON group hello from ron" "(group)"
    sleep $DELAY_USER_HELLO_MSG
    check_output beth "\[.*\] \[ron .*] group hello from ron" "Beth got group"
    check_output bob "\[.*\] \[ron .*] group hello from ron" "Bob got group"
}


Test_010_Client_commands() {
    printf "%s%s%s\n" "${BOLD}${WHITE}" "Test 010: Client commands" "${RESET}" >&2
for client in ron beth bob; do
    if [[ "${CLIENT_EXPECTED_EXIT[$client]:-false}" == true ]]; then
        continue
    fi

if tmux list-windows -t "$TMUX_SESSION" 2>/dev/null | awk -F: '{print $2}' | grep -qw "$client"; then
    : # still alive
else
    HAS_FAILED=true
    FAILED_DESC="Client $client died silently before end of tests"
    FAILED_TARGET="$client"
    FAILED_OUTPUT="No tmux window found at final check"
    print_final_failure_banner
    exit 1
fi
done

    send_cmd ron "pubk beth" "(pubk beth)"
    sleep $DELAY_USER_SHOW_PUBK
    check_output ron "pubkey beth" "Ron fetched beth pubkey" 5

    send_cmd ron "pubk bob" "(pubk bob)"
    sleep $DELAY_USER_SHOW_PUBK
    check_output ron "pubkey bob" "Ron fetched bob pubkey" 5

    send_cmd beth "pubk ron" "(pubk ron)"
    sleep $DELAY_USER_SHOW_PUBK
    check_output beth "pubkey ron" "Beth fetched ron pubkey" 5

    send_cmd beth "pubk bob" "(pubk bob)"
    sleep $DELAY_USER_SHOW_PUBK
    check_output beth "pubkey bob" "Beth fetched bob pubkey" 5

    send_cmd bob "pubk ron" "(pubk ron)"
    sleep $DELAY_USER_SHOW_PUBK
    check_output bob "pubkey ron" "Bob fetched ron pubkey" 5

    send_cmd bob "pubk beth" "(pubk beth)"
    sleep $DELAY_USER_SHOW_PUBK
    check_output bob "pubkey beth" "Bob fetched beth pubkey" 5
}
    # ====================== DELIBERATE FAILURE FOR TESTING ======================
    # Remove or comment out these lines for normal runs
    #printf "%s%s%s\n" "${BOLD}${BRIGHT_RED}" "=== FORCED FAILURE TEST ===" "${RESET}" >&2
    #check_output ron "THIS_PATTERN_WILL_NEVER_APPEAR_987654321" "Deliberate failure check - should trigger FAIL and stop script"
    # ====================== END OF FORCED FAILURE ======================



Test_011_Post_Ron_reconnect_full_verification() {
    printf "%s%s%s\n" "${BOLD}${WHITE}" "Test 011: Full verification after Ron reconnect" "${RESET}" >&2

    send_cmd ron "q" "(quit ron)"
    sleep $DELAY_USER_QUIT
    tmux kill-window -t "$TMUX_SESSION:ron" || true
    sleep $DELAY_TMUX_SHUTDOWN

    tmux new-window -t "$TMUX_SESSION:1" -n ron
    send_cmd ron "$CLIENT_BIN $IP $PORT ron $KEY_RON_PEM $CERT_RON --sessionid $SESSION_ID" "(ron login)"
    sleep $DELAY_USER_CONNECT_INIT

    check_output ron "TLS handshake successful" "Ron reconnected"
    check_output ron "peer beth ready" "Ron ready with beth (post-reconnect)" 45
    check_output ron "peer bob ready" "Ron ready with bob (post-reconnect)" 45

    #sleep 5

    extract_fps_from_client "ron" "post-reconnect"

    send_cmd ron "$FP_BOB_FROM_RON post-reconnect hi bob from ron" "(post-reconnect ron→bob)"
    sleep $DELAY_USER_HELLO_MSG
    check_output bob "\[.*\] \[ron .*] post-reconnect hi bob from ron" "Bob got post-reconnect"

    send_cmd beth "$FP_BOB_FROM_BETH post-reconnect hi bob from beth" "(post-reconnect beth→bob)"
    sleep $DELAY_USER_HELLO_MSG
    check_output bob "\[.*\] \[beth .*] post-reconnect hi bob from beth" "Bob got post-reconnect from beth"

    send_cmd bob "$FP_RON_FROM_BOB post-reconnect hi ron from bob" "(post-reconnect bob→ron)"
    sleep $DELAY_USER_HELLO_MSG
    check_output ron "\[.*\] \[bob .*] post-reconnect hi ron from bob" "Ron got post-reconnect from bob"

    #sleep 3

    #send_cmd ron "$FP_BETH_FROM_RON,$FP_BOB_FROM_RON post-reconnect group" "(post-reconnect group)"
    #sleep 2
    #check_output beth "\[.*\] \[ron .*] post-reconnect group" "Beth got post-reconnect group" 5
    #check_output bob "\[.*\] \[ron .*] post-reconnect group" "Bob got post-reconnect group" 5

    send_cmd ron "list users" "(post-reconnect list)"
    sleep $DELAY_USER_LISTUSER
    check_output ron "beth.*\[.*\]" "List shows beth (post-reconnect)"
    check_output ron "bob.*\[.*\]" "List shows bob (post-reconnect)"

    #send_cmd ron "pubk beth" "(post-reconnect pubk)"
    #sleep $DELAY_USER_SHOW_PUBK
    #check_client_alive ron "Ron survived pubk after reconnect"
    #check_output ron "pubkey beth" "Pubkey fetch works (post-reconnect)"
}

Test_012_Server_restart_full_verification() {
    printf "%s%s%s\n" "${BOLD}${WHITE}" "Test 012: Full verification after server restart" "${RESET}" >&2

    printf "%s%s%s\n" "${BOLD}${WHITE}" "Killing server..." "${RESET}" >&2
    pkill -f "^${SERVER_BIN} ${PORT}$"
    sleep $DELAY_SERVER_SHUTDOWN

    check_output ron "reconnecting in" "Ron detects server down" 3
    check_output beth "reconnecting in" "Beth detects server down" 3
    check_output bob "reconnecting in" "Bob detects server down" 3

    printf "%s%s%s\n" "${BOLD}${WHITE}" "Restarting server..." "${RESET}" >&2
    tmux new-window -t "$TMUX_SESSION:4" -n server_new
    tmux rename-window -t "$TMUX_SESSION:4" server
    send_cmd server "$SERVER_BIN $PORT" "(server restart)"
    sleep $DELAY_SERVER_START
    nc -z "$IP" "$PORT" && log "Server back online" || (log "FAIL: Server restart failed"; return 1)

    check_output ron "TLS handshake successful" "Ron reconnected after server restart" 1
    check_output beth "TLS handshake successful" "Beth reconnected after server restart" 1
    check_output bob "TLS handshake successful" "Bob reconnected after server restart" 1

    extract_fps_from_client "ron" "after server restart"

    send_cmd ron "$FP_BOB_FROM_RON after-restart hi bob from ron" "(after-restart ron→bob)"
    sleep $DELAY_USER_HELLO_MSG
    check_output bob "\[.*\] \[ron .*] after-restart hi bob from ron" "Bob got after restart"

    send_cmd ron "$FP_BETH_FROM_RON,$FP_BOB_FROM_RON after-restart group" "(after-restart group)"
    sleep $DELAY_USER_GRP
    check_output beth "\[.*\] \[ron .*] after-restart group" "Beth got after restart group"
    check_output bob "\[.*\] \[ron .*] after-restart group" "Bob got after restart group"

    send_cmd ron "list users" "(list after restart)"
    sleep $DELAY_USER_LISTUSER
    check_output ron "beth.*\[.*\]" "List works after restart"
    check_output ron "bob.*\[.*\]" "List works after restart"

    send_cmd ron "pubk beth" "(pubk after restart)"
    sleep $DELAY_USER_SHOW_PUBK
	check_client_alive ron "Ron survived pubk after reconnect"
    check_output ron "pubkey beth" "Pubkey works after restart"
}
print_final_failure_banner() {
    printf "\n%s%s%s\n" "${BOLD}${BRIGHT_RED}" "════════════════════════════════════════════════════════════════" "${RESET}"
    printf "%s%s%s\n" "${BOLD}${BRIGHT_RED}" "                           TEST FAILED                             " "${RESET}"
    printf "%s%s%s\n" "${BOLD}${BRIGHT_RED}" "  ════════════════════════════════════════════════════════════════" "${RESET}"

    printf "\n%s%s%s\n" "${BOLD}${WHITE}" "FAILED CHECK:" "${RESET}"
    printf "   %s%s%s\n" "${BOLD}${BRIGHT_RED}" "$FAILED_DESC" "${RESET}"

    printf "\n%s%s%s\n" "${BOLD}${WHITE}" "EXPECTED PATTERN:" "${RESET}"
    printf "   %s%s%s\n" "${BOLD}${YELLOW}" "$FAILED_PATTERN" "${RESET}"

    printf "\n%s%s%s\n" "${BOLD}${WHITE}" "LAST OUTPUT FROM $FAILED_TARGET:" "${RESET}"
    printf "%s%s%s\n" "${BOLD}${WHITE}" "$FAILED_OUTPUT" "${RESET}"

    printf "\n%s%s%s\n" "${BOLD}${BRIGHT_RED}" "════════════════════════════════" "${RESET}"
    printf "%s%s%s\n" "${BOLD}${BRIGHT_RED}" "         TEST SUITE ABORTED         " "${RESET}"
    printf "%s%s%s\n" "${BOLD}${BRIGHT_RED}" "  ════════════════════════════════" "${RESET}"
}


printf "%s%s%s\n" "${BOLD}${WHITE}" "=== STARTING FULL SPRK TEST SUITE ===" "${RESET}" >&2

TESTS=(
    #Test_001_Client_help
    EXEC_002_Start_server
    Test_003_Ron_connect
    Test_004_Beth_connect
    Test_005_Ron_Beth_messaging_and_fp_extraction
    Test_006_Bob_connect
    Test_007_Extract_all_fps_after_bob
    Test_008_Triangular_messaging
    Test_009_Multi_recipient
    Test_010_Client_commands
    Test_011_Post_Ron_reconnect_full_verification
    #Test_012_Server_restart_full_verification
)

run_test() {
    local t=$1
    printf "%s%s%s\n" "${BOLD}${WHITE}" "RUNNING: $t" "${RESET}" >&2
    if ! "$t"; then
        HAS_FAILED=true
        FAILED_DESC="${FAILED_DESC:-$t failed}"
        FAILED_TARGET="${FAILED_TARGET:-$t}"
        print_final_failure_banner
        exit 1
    fi
}

for t in "${TESTS[@]}"; do
    run_test "$t"
done

for client in ron beth bob; do
    if [[ "${CLIENT_EXPECTED_EXIT[$client]:-false}" == true ]]; then
        continue
    fi

if tmux list-windows -t "$TMUX_SESSION" 2>/dev/null | awk -F: '{print $2}' | grep -qw "$client"; then
    : # still alive
else
    HAS_FAILED=true
    FAILED_DESC="Client $client died silently before end of tests"
    FAILED_TARGET="$client"
    FAILED_OUTPUT="No tmux window found at final check"
    print_final_failure_banner
    exit 1
fi
done

if [ "$HAS_FAILED" = false ]; then
    printf "\n%s%s%s\n" "${BOLD}${BRIGHT_GREEN}" "════════════════════════════════════════════════════════" "${RESET}"
    printf "%s%s%s\n" "${BOLD}${BRIGHT_GREEN}" "                ALL TESTS COMPLETED - PASS            " "${RESET}"
    printf "%s%s%s\n" "${BOLD}${BRIGHT_GREEN}" "  ════════════════════════════════════════════════════════" "${RESET}"

    for check in "${PASSED_CHECKS[@]}"; do
        printf "   %s✓%s %s\n" "${BRIGHT_GREEN}" "${RESET}" "$check"
    done

    printf "\n%s%s%s\n" "${BOLD}${BRIGHT_GREEN}" "═══════════════════════════════════════════════════════════════════════════" "${RESET}"
    printf "%s%s%s\n" "${BOLD}${WHITE}" "Total successful checks: ${#PASSED_CHECKS[@]}" "${RESET}"
    printf "%s%s%s\n" "${BOLD}${BRIGHT_GREEN}" "═══════════════════════════════════════════════════════════════════════════" "${RESET}"


    exit 0
fi

print_final_failure_banner
exit 1



