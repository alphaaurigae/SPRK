#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/bash/shared/default.sh"

FP_BETH_FROM_RON=""
FP_RON_FROM_BETH=""
FP_BOB_FROM_RON=""
FP_BOB_FROM_BETH=""
FP_RON_FROM_BOB=""
FP_BETH_FROM_BOB=""

TMUX_SESSION="sprk_test_$$"

DELAY_SERVER_START="1"
DELAY_USER_CONNECT_INIT="0.3"
DELAY_USER_CONNECT_EST="0.3"
DELAY_USER_HELLO_MSG="0.3"
DELAY_USER_LISTUSER="0.3"
DELAY_USER_SHOW_PUBK="0.3"
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

send_cmd() {
	local target=$1 cmd=$2 desc=${3:-""}
	printf "%s%s%s%s\n" "${BOLD}${WHITE}" "STATUS:" "${RESET}" " >>> Sending to $target: '$cmd' $desc" >&2
	tmux send-keys -t "$TMUX_SESSION:$target" "$cmd" C-m
}

print_final_failure_banner() {
	printf "%s%s%s\n" "${BOLD}${BRIGHT_RED}" "TEST FAILED" "${RESET}"
	printf "\n%s%s%s\n" "${BOLD}${WHITE}" "FAILED CHECK:" "${RESET}"
	printf "   %s%s%s\n" "${BOLD}${BRIGHT_RED}" "$FAILED_DESC" "${RESET}"
	printf "\n%s%s%s\n" "${BOLD}${WHITE}" "EXPECTED PATTERN:" "${RESET}"
	printf "   %s%s%s\n" "${BOLD}${YELLOW}" "$FAILED_PATTERN" "${RESET}"
	printf "\n%s%s%s\n" "${BOLD}${WHITE}" "LAST OUTPUT FROM $FAILED_TARGET:" "${RESET}"
	printf "%s%s%s\n" "${BOLD}${WHITE}" "$FAILED_OUTPUT" "${RESET}"
	printf "%s%s%s\n" "${BOLD}${BRIGHT_RED}" "TEST SUITE ABORTED" "${RESET}"
}

check_output() {
	local target=$1 pattern=$2 desc=$3 timeout=${4:-2} waited=0 grace_period=3
	printf "%s\n" "DEBUG: check_output target=${target} pattern=${pattern} timeout=${timeout}" >&2
	while (( waited < timeout )); do
		if (( waited >= grace_period )); then
			if ! tmux list-windows -t "$TMUX_SESSION" 2>/dev/null | grep -qE "^[0-9]+: $target([*[:space:]]|$)"; then
				HAS_FAILED=true; FAILED_DESC="Client $target crashed during check: $desc"
				FAILED_TARGET="$target"; FAILED_OUTPUT="tmux window gone"; FAILED_PATTERN="$pattern"
				print_final_failure_banner; exit 1
			fi
		fi
		local output
		output=$(tmux capture-pane -p -S -3000 -t "$TMUX_SESSION:$target" 2>/dev/null || echo "ERROR: capture failed")
		local output_normalized
		output_normalized=$(echo "$output" | tr -d '\n\r' | tr -s ' ')
		if echo "$output_normalized" | grep -qE "$pattern"; then
			printf "%s%s%s%s\n" "${BOLD}${BRIGHT_GREEN}" "PASS:" "${RESET}" " $desc" >&2
			PASSED_CHECKS+=("$desc"); return 0
		fi
		sleep 1; ((waited++))
	done
	HAS_FAILED=true; FAILED_DESC="$desc"; FAILED_PATTERN="$pattern"; FAILED_OUTPUT="$output"; FAILED_TARGET="$target"
	printf "%s%s%s%s\n" "${BOLD}${BRIGHT_RED}" "FAIL:" "${RESET}" " $desc (timeout ${timeout}s)" >&2
	print_final_failure_banner; exit 1
}

extract_fps_from_client() {
	local client=$1 desc=$2
	printf "%s%s%s%s\n" "${BOLD}${WHITE}" "STATUS:" "${RESET}" " Extracting FPs from $client ($desc)" >&2
	send_cmd "$client" "list users" "(extract FPs)"
	sleep $DELAY_SERVER_START
	local output
	output=$(tmux capture-pane -p -t "$TMUX_SESSION:$client" 2>/dev/null)
	local ron_fp=$(echo "$output" | grep -oE "ron \[([a-f0-9]{64})\]" | grep -oE "[a-f0-9]{64}" | head -1)
	local beth_fp=$(echo "$output" | grep -oE "beth \[([a-f0-9]{64})\]" | grep -oE "[a-f0-9]{64}" | head -1)
	local bob_fp=$(echo "$output" | grep -oE "bob \[([a-f0-9]{64})\]" | grep -oE "[a-f0-9]{64}" | head -1)
	case "$client" in
		ron)  [[ -n "$beth_fp" ]] && FP_BETH_FROM_RON="$beth_fp"; [[ -n "$bob_fp" ]] && FP_BOB_FROM_RON="$bob_fp" ;;
		beth) [[ -n "$ron_fp" ]] && FP_RON_FROM_BETH="$ron_fp"; [[ -n "$bob_fp" ]] && FP_BOB_FROM_BETH="$bob_fp" ;;
		bob)  [[ -n "$ron_fp" ]] && FP_RON_FROM_BOB="$ron_fp"; [[ -n "$beth_fp" ]] && FP_BETH_FROM_BOB="$beth_fp" ;;
	esac
}

cleanup() {
	pkill -f "^${SERVER_BIN} ${SERVER_PORTV4}$" || true
	pkill -f "${CLIENT_BIN}.*${SERVER_PORTV4}" || true
	tmux kill-session -t "$TMUX_SESSION" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

Test_001_Client_help() {
	local out=$("$CLIENT_BIN" 2>&1 || true)
	[[ $out == *"Usage: chat_client"* ]] || return 1
}

EXEC_002_Start_server() {
	tmux new-session -d -s "$TMUX_SESSION" -c "$SCRIPT_DIR"
	tmux rename-window -t "$TMUX_SESSION:0" server
	send_cmd server "$SERVER_BIN $SERVER_PORTV4" "(start server)"
	sleep $DELAY_SERVER_START
	nc -z "$SERVER_IPV4" "$SERVER_PORTV4" || return 1
}

Test_003_Ron_connect() {
	tmux new-window -t "$TMUX_SESSION:1" -n ron
	send_cmd ron "$CLIENT_BIN $SERVER_IPV4 $SERVER_PORTV4 ron $KEY_RON_PEM $CERT_RON --sessionid $SESSION_ID_001" "(ron login)"
	sleep $DELAY_USER_CONNECT_INIT
	check_output ron "TLS handshake successful" "Ron connected"
	sleep $DELAY_USER_CONNECT_EST
	check_output server "connect ron session=.*" "Server sees ron"
}

Test_004_Beth_connect() {
	tmux new-window -t "$TMUX_SESSION:2" -n beth
	send_cmd beth "$CLIENT_BIN $SERVER_IPV4 $SERVER_PORTV4 beth $KEY_BETH_PEM $CERT_BETH --sessionid $SESSION_ID_001" "(beth login)"
	sleep $DELAY_USER_CONNECT_INIT
	check_output beth "TLS handshake successful" "Beth connected"
	check_output beth "peer ron ready" "Beth ready with ron" 10
}

Test_005_Ron_Beth_bidir_messaging() {
	extract_fps_from_client "ron" "after connect"
	extract_fps_from_client "beth" "from Beth's view"
	# Both directions before checking either -- regression test for the fixed
	# cross-direction nonce reuse (both sides at seq=0 simultaneously).
	send_cmd ron "$FP_BETH_FROM_RON hello beth from ron" "(ron->beth)"
	send_cmd beth "$FP_RON_FROM_BETH hello ron from beth" "(beth->ron)"
	sleep $DELAY_USER_HELLO_MSG
	check_output beth "\[.*\] \[ron .*] hello beth from ron" "Beth received from ron"
	check_output ron "\[.*\] \[beth .*] hello ron from beth" "Ron received from beth"
}

Test_006_Bob_connect_and_triangular() {
	tmux new-window -t "$TMUX_SESSION:3" -n bob
	send_cmd bob "$CLIENT_BIN $SERVER_IPV4 $SERVER_PORTV4 bob $KEY_BOB_PEM $CERT_BOB --sessionid $SESSION_ID_001" "(bob login)"
	sleep $DELAY_USER_CONNECT_INIT
	check_output bob "TLS handshake successful" "Bob connected"
	check_output bob "peer ron ready" "Bob ready with ron" 45
	check_output bob "peer beth ready" "Bob ready with beth" 45
	extract_fps_from_client "ron" "after bob"
	extract_fps_from_client "beth" "after bob"
	extract_fps_from_client "bob" "after bob"

	send_cmd ron "$FP_BOB_FROM_RON hi bob from ron" "(ron->bob)"; sleep $DELAY_USER_HELLO_MSG
	check_output bob "\[.*\] \[ron .*] hi bob from ron" "Bob got from ron"
	send_cmd bob "$FP_RON_FROM_BOB hi ron from bob" "(bob->ron)"; sleep $DELAY_USER_HELLO_MSG
	check_output ron "\[.*\] \[bob .*] hi ron from bob" "Ron got from bob"
	send_cmd bob "$FP_BETH_FROM_BOB hi beth from bob" "(bob->beth)"; sleep $DELAY_USER_HELLO_MSG
	check_output beth "\[.*\] \[bob .*] hi beth from bob" "Beth got from bob"
	send_cmd beth "$FP_BOB_FROM_BETH hi bob from beth" "(beth->bob)"; sleep $DELAY_USER_HELLO_MSG
	check_output bob "\[.*\] \[beth .*] hi bob from beth" "Bob got from beth"
}

Test_007_Multi_recipient() {
	send_cmd ron "$FP_BETH_FROM_RON,$FP_BOB_FROM_RON group hello from ron" "(group)"
	sleep $DELAY_USER_HELLO_MSG
	check_output beth "\[.*\] \[ron .*] group hello from ron" "Beth got group"
	check_output bob "\[.*\] \[ron .*] group hello from ron" "Bob got group"
}

Test_008_Beth_disconnect_reconnect_then_message_all() {
	# The user-specified scenario this test exists for: a mid-session
	# disconnect/reconnect of ONE party in a 3-way chat, then verify BOTH
	# directions with BOTH other parties still work afterward -- this is what
	# originally exposed the "reconnect leaves other clients' ready state
	# stale" bug (fixed via the target_fp wire-protocol addition).
	send_cmd beth "q" "(beth disconnects)"
	sleep $DELAY_USER_QUIT
	tmux kill-window -t "$TMUX_SESSION:beth" || true
	sleep $DELAY_TMUX_SHUTDOWN

	tmux new-window -t "$TMUX_SESSION:2" -n beth
	send_cmd beth "$CLIENT_BIN $SERVER_IPV4 $SERVER_PORTV4 beth $KEY_BETH_PEM $CERT_BETH --sessionid $SESSION_ID_001" "(beth rejoins)"
	sleep $DELAY_USER_CONNECT_INIT
	check_output beth "TLS handshake successful" "Beth reconnected"
	check_output beth "peer ron ready" "Beth ready with ron post-reconnect" 45
	check_output beth "peer bob ready" "Beth ready with bob post-reconnect" 45

	extract_fps_from_client "beth" "post-reconnect"

	send_cmd beth "$FP_BOB_FROM_BETH beth to bob post-reconnect" "(beth->bob)"; sleep $DELAY_USER_HELLO_MSG
	check_output bob "\[.*\] \[beth .*] beth to bob post-reconnect" "Bob got beth's post-reconnect message"
	send_cmd beth "$FP_RON_FROM_BETH beth to ron post-reconnect" "(beth->ron)"; sleep $DELAY_USER_HELLO_MSG
	check_output ron "\[.*\] \[beth .*] beth to ron post-reconnect" "Ron got beth's post-reconnect message"
}

Test_009_Bob_disconnect_ron_beth_continue() {
	send_cmd bob "q" "(bob disconnects)"
	sleep $DELAY_USER_QUIT
	send_cmd ron "$FP_BETH_FROM_RON ron to beth while bob is down" "(ron->beth)"; sleep $DELAY_USER_HELLO_MSG
	check_output beth "\[.*\] \[ron .*] ron to beth while bob is down" "Beth got ron's message while bob is down"
	send_cmd beth "$FP_RON_FROM_BETH beth to ron while bob is down" "(beth->ron)"; sleep $DELAY_USER_HELLO_MSG
	check_output ron "\[.*\] \[beth .*] beth to ron while bob is down" "Ron got beth's message while bob is down"
}

Test_010_Bob_reconnect_full_triangle_again() {
	tmux new-window -t "$TMUX_SESSION:3" -n bob
	send_cmd bob "$CLIENT_BIN $SERVER_IPV4 $SERVER_PORTV4 bob $KEY_BOB_PEM $CERT_BOB --sessionid $SESSION_ID_001" "(bob reconnects)"
	sleep $DELAY_USER_CONNECT_INIT
	check_output bob "TLS handshake successful" "Bob reconnected"
	check_output bob "peer ron ready" "Bob ready with ron post-reconnect" 45
	check_output bob "peer beth ready" "Bob ready with beth post-reconnect" 45

	extract_fps_from_client "bob" "final"
	send_cmd bob "$FP_RON_FROM_BOB bob to ron final" "(bob->ron)"; sleep $DELAY_USER_HELLO_MSG
	check_output ron "\[.*\] \[bob .*] bob to ron final" "Ron got bob's final message"
	send_cmd bob "$FP_BETH_FROM_BOB bob to beth final" "(bob->beth)"; sleep $DELAY_USER_HELLO_MSG
	check_output beth "\[.*\] \[bob .*] bob to beth final" "Beth got bob's final message"
}

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

TESTS=(
	Test_001_Client_help
	EXEC_002_Start_server
	Test_003_Ron_connect
	Test_004_Beth_connect
	Test_005_Ron_Beth_bidir_messaging
	Test_006_Bob_connect_and_triangular
	Test_007_Multi_recipient
	Test_008_Beth_disconnect_reconnect_then_message_all
	Test_009_Bob_disconnect_ron_beth_continue
	Test_010_Bob_reconnect_full_triangle_again
)

main() {
	HAS_FAILED=false
	for t in "${TESTS[@]}"; do run_test "$t"; done
	if [ "$HAS_FAILED" = false ]; then
		printf "%s%s%s\n" "${BOLD}${BRIGHT_GREEN}" "ALL TESTS PASS" "${RESET}"
		for check in "${PASSED_CHECKS[@]}"; do printf "   ✓ %s\n" "$check"; done
		printf "Total successful checks: %d\n" "${#PASSED_CHECKS[@]}"
		exit 0
	fi
	exit 1
}

main
