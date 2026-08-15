#!/usr/bin/env bash
# Network Sweeper Linux launcher — download a release binary, verify SHA256, run or install.
# Copyright (C) 2026 Bernard Visagie
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Default (interactive Enter, or no TTY): ephemeral run from a temp dir.
# Prompts read /dev/tty so `curl | bash` still works.
set -euo pipefail

REPO="BVisagie/network-sweeper"
RELEASE_BASE="https://github.com/${REPO}/releases/latest/download"
RELEASES_PAGE="https://github.com/${REPO}/releases"
DEFAULT_PREFIX="${HOME:+$HOME/.local/bin}"

MODE=""          # ephemeral | install
LAUNCH=1         # 0 = install only
PREFIX=""
NO_BROWSER=0
SKIP_MENU=0
WANT_SUDO=0      # 1 = --sudo or menu “run once with sudo”
WORKDIR=""

# UI palette matches web/style.css (--accent #3ecf8e, --fg #e7f2ec, --muted, --danger).
RESET="" ACCENT="" FG="" MUTED="" DANGER="" BOLD="" DIM=""
if [[ -z "${NO_COLOR:-}" ]]; then
	if [[ -t 1 ]] || { [[ -w /dev/tty ]] && [[ -c /dev/tty ]]; }; then
		RESET=$'\033[0m'
		ACCENT=$'\033[38;2;62;207;142m'
		FG=$'\033[38;2;231;242;236m'
		MUTED=$'\033[38;2;138;163;150m'
		DANGER=$'\033[38;2;224;107;99m'
		BOLD=$'\033[1m'
		DIM=$'\033[2m'
	fi
fi

usage() {
	cat <<EOF
Network Sweeper Linux launcher

Usage:
  curl -fsSL https://raw.githubusercontent.com/${REPO}/main/scripts/install.sh | bash
  bash scripts/install.sh [options]

Default with a terminal: interactive menu (Enter = run once, ephemeral).
Default without a terminal: ephemeral run.

Options:
  --ephemeral       Run once from a temp dir (no PATH install)
  --install         Install to --prefix (or ~/.local/bin) and launch
  --install-only    Install to --prefix (or ~/.local/bin) and exit
  --prefix DIR      Install directory (implies install, not ephemeral)
  --sudo            After verify, launch the binary with sudo (not this script)
  --no-browser      Pass -no-browser to the binary (also auto on headless)
  -h, --help        Show this help

sudo curl | bash only elevates curl, not this app. Do not curl | sudo bash
(that runs the installer as root). Elevate the verified binary instead:
  curl -fsSL …/install.sh | bash -s -- --sudo
After a persistent install:
  sudo network-sweeper
EOF
}

die() {
	printf '%s%s%s\n' "$DANGER" "$*" "$RESET" >&2
	exit 1
}

info() {
	printf '%s%s%s\n' "$MUTED" "$*" "$RESET" >&2
}

ok() {
	printf '%s%s%s\n' "$ACCENT" "$*" "$RESET" >&2
}

cleanup() {
	if [[ -n "${WORKDIR:-}" && -d "$WORKDIR" ]]; then
		rm -rf "$WORKDIR"
	fi
}

has_tty() {
	[[ -e /dev/tty && -r /dev/tty && -w /dev/tty ]]
}

ui() {
	if has_tty; then
		printf '%s' "$*" >/dev/tty
	else
		printf '%s' "$*" >&2
	fi
}

ui_nl() {
	ui "$*"$'\n'
}

no_display() {
	[[ -z "${DISPLAY:-}" && -z "${WAYLAND_DISPLAY:-}" ]]
}

want_no_browser() {
	[[ "$NO_BROWSER" -eq 1 ]] || no_display
}

in_path() {
	case ":${PATH}:" in
	*":$1:"*) return 0 ;;
	*) return 1 ;;
	esac
}

expand_user_path() {
	local p=$1
	if [[ "$p" == "~" ]]; then
		p="${HOME:?HOME is not set}"
	elif [[ "$p" == "~/"* ]]; then
		p="${HOME:?HOME is not set}/${p#~/}"
	fi
	if [[ "$p" != /* ]]; then
		p="$(pwd)/$p"
	fi
	printf '%s' "$p"
}

linux_arch() {
	local m
	m=$(uname -m)
	case "$m" in
	x86_64 | amd64) printf 'amd64' ;;
	aarch64 | arm64) printf 'arm64' ;;
	*) die "Unsupported Linux architecture: $m. Download a binary from ${RELEASES_PAGE}" ;;
	esac
}

read_tty() {
	local reply=""
	if ! read -r reply </dev/tty; then
		die "Could not read from the terminal."
	fi
	printf '%s' "$reply"
}

cancel_ui() {
	ui_nl "${MUTED}Cancelled.${RESET}"
	exit 0
}

# prompt_yn MESSAGE DEFAULT  → prints y or n (empty input = DEFAULT; DEFAULT is y or n)
prompt_yn() {
	local message=$1 default=$2
	local reply cleaned
	while true; do
		ui "$message"
		reply=$(read_tty)
		cleaned=${reply//[[:space:]]/}
		if [[ -z "$cleaned" ]]; then
			printf '%s' "$default"
			return
		fi
		if [[ "$cleaned" == [qQ] ]]; then
			cancel_ui
		fi
		if [[ "$cleaned" == [yY] || "$cleaned" == [yY][eE][sS] ]]; then
			printf 'y'
			return
		fi
		if [[ "$cleaned" == [nN] || "$cleaned" == [nN][oO] ]]; then
			printf 'n'
			return
		fi
		ui_nl "${DANGER}Please enter y or n (or q to cancel).${RESET}"
	done
}

# prompt_choice MESSAGE DEFAULT MAX  → prints 1..MAX (empty input = DEFAULT)
prompt_choice() {
	local message=$1 default=$2 max=$3
	local reply cleaned
	while true; do
		ui "$message"
		reply=$(read_tty)
		cleaned=${reply//[[:space:]]/}
		if [[ -z "$cleaned" ]]; then
			printf '%s' "$default"
			return
		fi
		if [[ "$cleaned" == [qQ] ]]; then
			cancel_ui
		fi
		if [[ "$cleaned" =~ ^[1-9][0-9]*$ ]] && ((cleaned >= 1 && cleaned <= max)); then
			printf '%s' "$cleaned"
			return
		fi
		ui_nl "${DANGER}Please enter a number 1–${max} (or q to cancel).${RESET}"
	done
}

banner() {
	ui_nl ""
	ui_nl "  ${ACCENT}${BOLD}Network Sweeper${RESET}"
	ui_nl "  ${MUTED}local LAN inventory${RESET}"
	ui_nl "  ${DIM}────────────────────────────────────────${RESET}"
	ui_nl ""
}

interactive_menu() {
	banner
	ui_nl "  ${FG}How would you like to proceed?${RESET}"
	ui_nl ""
	ui_nl "    ${ACCENT}1)${RESET}  ${FG}Run once (ephemeral)${RESET}           ${MUTED}default — nothing left on PATH${RESET}"
	ui_nl "    ${FG}2)${RESET}  ${FG}Run once with sudo${RESET}             ${MUTED}Deep discovery (ICMP + ARP)${RESET}"
	ui_nl "    ${FG}3)${RESET}  ${FG}Install to a directory${RESET}         ${MUTED}keep network-sweeper for later${RESET}"
	ui_nl ""
	ui_nl "  ${MUTED}sudo curl | bash only elevates curl. Choose 2, or install then: sudo network-sweeper${RESET}"
	ui_nl "  ${MUTED}q to cancel${RESET}"
	ui_nl ""
	local step1
	step1=$(prompt_choice "  ${ACCENT}Choice [1]:${RESET} " 1 3)
	ui_nl ""
	if [[ "$step1" == 1 ]]; then
		MODE=ephemeral
		return
	fi
	if [[ "$step1" == 2 ]]; then
		MODE=ephemeral
		WANT_SUDO=1
		return
	fi

	MODE=install
	LAUNCH=1
	ui_nl "  ${FG}Install location${RESET}"
	ui_nl ""
	ui_nl "    ${ACCENT}1)${RESET}  ${FG}Default${RESET}  ${MUTED}${DEFAULT_PREFIX}${RESET}"
	ui_nl "    ${FG}2)${RESET}  ${FG}Custom path${RESET}"
	ui_nl ""
	local step2
	step2=$(prompt_choice "  ${ACCENT}Choice [1]:${RESET} " 1 2)
	ui_nl ""
	if [[ "$step2" == 1 ]]; then
		[[ -n "${DEFAULT_PREFIX}" ]] || die "HOME is not set; pass --prefix DIR"
		PREFIX=$DEFAULT_PREFIX
	else
		local typed=""
		while [[ -z "$typed" ]]; do
			ui "  ${FG}Directory:${RESET} "
			typed=$(read_tty)
			typed=${typed#"${typed%%[![:space:]]*}"}
			typed=${typed%"${typed##*[![:space:]]}"}
			if [[ -z "$typed" ]]; then
				ui_nl "${DANGER}Enter a directory, or q to cancel.${RESET}"
				continue
			fi
			if [[ "$typed" == [qQ] ]]; then
				cancel_ui
			fi
		done
		PREFIX=$(expand_user_path "$typed")
	fi

	ui_nl "  ${FG}After copying the binary${RESET}"
	ui_nl ""
	ui_nl "    ${ACCENT}1)${RESET}  ${FG}Install and launch${RESET}     ${MUTED}default${RESET}"
	ui_nl "    ${FG}2)${RESET}  ${FG}Install only${RESET}"
	ui_nl ""
	local step3
	step3=$(prompt_choice "  ${ACCENT}Choice [1]:${RESET} " 1 2)
	ui_nl ""
	if [[ "$step3" == 2 ]]; then
		LAUNCH=0
	fi
}

parse_args() {
	while [[ $# -gt 0 ]]; do
		case "$1" in
		-h | --help)
			usage
			exit 0
			;;
		--ephemeral)
			[[ -z "$MODE" || "$MODE" == ephemeral ]] || die "--ephemeral cannot be combined with install flags"
			MODE=ephemeral
			SKIP_MENU=1
			shift
			;;
		--install)
			[[ -z "$MODE" || "$MODE" == install ]] || die "--install cannot be combined with --ephemeral"
			MODE=install
			LAUNCH=1
			SKIP_MENU=1
			shift
			;;
		--install-only)
			[[ -z "$MODE" || "$MODE" == install ]] || die "--install-only cannot be combined with --ephemeral"
			MODE=install
			LAUNCH=0
			SKIP_MENU=1
			shift
			;;
		--prefix)
			[[ $# -ge 2 ]] || die "--prefix needs a directory"
			[[ -z "$MODE" || "$MODE" == install ]] || die "--prefix cannot be combined with --ephemeral"
			MODE=install
			PREFIX=$(expand_user_path "$2")
			SKIP_MENU=1
			shift 2
			;;
		--sudo)
			WANT_SUDO=1
			SKIP_MENU=1
			shift
			;;
		--no-browser)
			NO_BROWSER=1
			shift
			;;
		*)
			die "Unknown option: $1 (try --help)"
			;;
		esac
	done
	if [[ "$WANT_SUDO" -eq 1 && "$LAUNCH" -eq 0 ]]; then
		die "--sudo cannot be combined with --install-only"
	fi
}

require_linux() {
	local sys
	sys=$(uname -s)
	if [[ "$sys" != Linux ]]; then
		die "This launcher is for Linux. Download a ${sys} binary from ${RELEASES_PAGE}"
	fi
	command -v curl >/dev/null || die "curl is required"
	command -v sha256sum >/dev/null || die "sha256sum is required (GNU coreutils)"
}

# Prints the verified binary path on stdout only.
download_and_verify() {
	local dest_dir=$1 arch asset sums
	arch=$(linux_arch)
	asset="network-sweeper-linux-${arch}"
	sums="SHA256SUMS"

	info "Downloading ${asset} from GitHub Releases…"
	if ! curl -fL --retry 2 -A "network-sweeper-install" --progress-bar \
		-o "${dest_dir}/${asset}" "${RELEASE_BASE}/${asset}"; then
		die "Could not download the latest Linux release (${asset}). Publish a GitHub Release, or download a binary from ${RELEASES_PAGE}"
	fi
	if ! curl -fsSL -A "network-sweeper-install" \
		-o "${dest_dir}/${sums}" "${RELEASE_BASE}/${sums}"; then
		die "Could not download SHA256SUMS. The installer will not run an unverified binary."
	fi

	info "Verifying SHA256…"
	if ! grep -E "[[:space:]]\\*?${asset}\$" "${dest_dir}/${sums}" >/dev/null; then
		die "SHA256SUMS does not list ${asset}. Refusing to continue."
	fi
	(
		cd "$dest_dir"
		grep -E "[[:space:]]\\*?${asset}\$" "$sums" | sha256sum -c -
	) >&2 || die "Checksum mismatch. Refusing to run or install."
	chmod 0755 "${dest_dir}/${asset}"
	printf '%s' "${dest_dir}/${asset}"
}

ensure_prefix() {
	local dir=$1
	[[ -n "$dir" ]] || die "Install directory is empty"
	[[ "$dir" != / ]] || die "Refusing to install into /"
	mkdir -p "$dir" || die "Could not create ${dir}"
	[[ -w "$dir" ]] || die "Cannot write to ${dir} (choose another --prefix, or install as a user into ~/.local/bin)"
}

path_hint() {
	local dir=$1
	if in_path "$dir"; then
		return
	fi
	info "Note: ${dir} is not on PATH. Add it with:"
	info "  export PATH=\"${dir}:\$PATH\""
}

sudo_cached() {
	command -v sudo >/dev/null || return 1
	sudo -n true >/dev/null 2>&1
}

note_no_browser() {
	if want_no_browser && no_display && [[ "$NO_BROWSER" -ne 1 ]]; then
		info "No display detected; dashboard URL will print below (loopback only)."
	fi
}

# When sudo credentials are cached (typical after `sudo curl | bash`), offer to
# elevate the verified binary. Otherwise print a one-line unprivileged notice.
maybe_want_sudo() {
	if [[ "$(id -u)" -eq 0 ]]; then
		WANT_SUDO=0
		return
	fi
	if [[ "$WANT_SUDO" -eq 1 ]]; then
		return
	fi
	if has_tty && sudo_cached; then
		ui_nl ""
		ui_nl "  ${FG}sudo curl | bash only elevates curl, not this app.${RESET}"
		ui_nl "  ${MUTED}Launch the verified binary with sudo for Deep discovery?${RESET}"
		ui_nl ""
		local yn
		yn=$(prompt_yn "  ${ACCENT}Launch with sudo [Y/n]:${RESET} " y)
		ui_nl ""
		if [[ "$yn" == y ]]; then
			WANT_SUDO=1
		fi
		return
	fi
	info "This session is not elevated. Deep discovery: re-run with --sudo, or sudo network-sweeper after install."
}

run_sudo() {
	local bin=$1
	local do_exec=$2
	command -v sudo >/dev/null || die "sudo is required to elevate"
	info "Launching the verified binary with sudo (not the installer script)."
	info "Opening a browser may fail; the dashboard URL prints below."
	note_no_browser
	if [[ "$do_exec" -eq 1 ]]; then
		if want_no_browser; then
			exec sudo --preserve-env=DISPLAY,WAYLAND_DISPLAY,XDG_RUNTIME_DIR -- "$bin" -no-browser || die "Failed to launch ${bin}"
		fi
		exec sudo --preserve-env=DISPLAY,WAYLAND_DISPLAY,XDG_RUNTIME_DIR -- "$bin" || die "Failed to launch ${bin}"
	fi
	if want_no_browser; then
		sudo --preserve-env=DISPLAY,WAYLAND_DISPLAY,XDG_RUNTIME_DIR -- "$bin" -no-browser
	else
		sudo --preserve-env=DISPLAY,WAYLAND_DISPLAY,XDG_RUNTIME_DIR -- "$bin"
	fi
}

run_binary() {
	local bin=$1
	note_no_browser
	if want_no_browser; then
		"$bin" -no-browser
	else
		"$bin"
	fi
}

# do_exec=1 replaces this process (install+launch). Ephemeral must wait so cleanup runs.
launch_binary() {
	local bin=$1
	local do_exec=$2
	if [[ "$(id -u)" -eq 0 ]]; then
		WANT_SUDO=0
		info "Running as root. Opening a browser may fail; the dashboard URL prints below."
	else
		maybe_want_sudo
	fi
	if [[ "$WANT_SUDO" -eq 1 ]]; then
		run_sudo "$bin" "$do_exec"
		return
	fi
	if [[ "$do_exec" -eq 1 ]]; then
		note_no_browser
		if want_no_browser; then
			exec "$bin" -no-browser || die "Failed to launch ${bin}"
		fi
		exec "$bin" || die "Failed to launch ${bin}"
	fi
	run_binary "$bin"
}

# Prints the installed path on stdout only.
install_binary() {
	local src=$1 dest
	[[ -n "$PREFIX" ]] || PREFIX=${DEFAULT_PREFIX:?HOME is not set; pass --prefix DIR}
	PREFIX=$(expand_user_path "$PREFIX")
	ensure_prefix "$PREFIX"
	dest="${PREFIX}/network-sweeper"
	cp -f "$src" "$dest"
	chmod 0755 "$dest"
	ok "Installed ${dest}"
	path_hint "$PREFIX"
	if [[ "$(id -u)" -eq 0 ]]; then
		info "Running as root. Prefer a user install to ~/.local/bin, then: sudo network-sweeper for Deep discovery only."
	else
		info "Deep discovery later: sudo ${dest}"
	fi
	printf '%s' "$dest"
}

main() {
	parse_args "$@"
	require_linux

	if [[ "$SKIP_MENU" -eq 0 ]]; then
		if has_tty; then
			interactive_menu
		else
			MODE=ephemeral
			info "No terminal detected; running once (ephemeral)."
		fi
	fi

	[[ -n "$MODE" ]] || MODE=ephemeral
	if [[ "$MODE" == install && -z "$PREFIX" ]]; then
		[[ -n "${DEFAULT_PREFIX}" ]] || die "HOME is not set; pass --prefix DIR"
		PREFIX=$DEFAULT_PREFIX
	fi

	WORKDIR=$(mktemp -d "${TMPDIR:-/tmp}/network-sweeper.XXXXXX")
	trap cleanup EXIT INT TERM

	local verified installed
	verified=$(download_and_verify "$WORKDIR")

	if [[ "$MODE" == ephemeral ]]; then
		ok "Running once from a temp directory (not installed)."
		launch_binary "$verified" 0
		return
	fi

	installed=$(install_binary "$verified")
	if [[ "$LAUNCH" -eq 0 ]]; then
		info "Launch later with: ${installed}"
		return
	fi
	cleanup
	WORKDIR=""
	trap - EXIT INT TERM
	launch_binary "$installed" 1
}

main "$@"
