#!/usr/bin/bash
set -u  # Safer scripting: treat unset variables as errors (prevents silent mistakes)

#======================================================
# CONFIGURATION & CONSTANTS (K1)
#======================================================

OPT_MOUNT="/opt"  # /opt mountpoint (normally read-only) (K1/K12)
SEC_BASE="/opt/security"  # All assets/logs for this script live under /opt/security (K1)
TMP_BASE="${SEC_BASE}/tmp"  # Base for working directories (S1)
ERR_BASE="${SEC_BASE}/errors"  # Where S8 error bundles are stored (S8)
BIN_BASE="${SEC_BASE}/bin"  # Location of validate + sectar tools (K1/S6)
VAL_TOOL="${BIN_BASE}/validate"  # validate tool (sha256sum-like) (S6)
SEC_TOOL="${BIN_BASE}/sectar"  # sectar/backtool tool (tar-like) (S6/S10)
GPG_USER="tht2023@tht.noroff.no"  # Signing identity for S13 (S13)
SSH_PORT="2069"  # SSH port required by the brief (K11)
PASSFILE="${SEC_BASE}/sign.pass"  # Non-interactive signing passphrase file (S13/S18)
SUBMIT_BASE="/submission"  # Remote submission base directory (S14)

#======================================================
# S7 + K12: Failure handling and environment restoration
#======================================================

ORIG_OPT_MODE="$(findmnt -no OPTIONS "$OPT_MOUNT" 2>/dev/null | grep -oE '\bro\b|\brw\b' | head -n1)"  # Detect /opt ro/rw
[ -n "${ORIG_OPT_MODE:-}" ] || ORIG_OPT_MODE="ro"  # Fallback to safest mode if detection fails

HOST_SHORT="$(hostname -s)"  # Host shortname for output lines (S16/S17)

opt_rw() { mount -o remount,rw "$OPT_MOUNT" 2>/dev/null || return 1; }  # Remount /opt read-write (K1)
opt_ro() { mount -o remount,ro "$OPT_MOUNT" 2>/dev/null || return 1; }  # Remount /opt read-only (K1)

restore_opt() {  # Restore /opt to its original mode from before execution (K12)
  if [ "$ORIG_OPT_MODE" = "ro" ]; then mount -o remount,ro "$OPT_MOUNT" 2>/dev/null || true; fi  # Restore ro
  if [ "$ORIG_OPT_MODE" = "rw" ]; then mount -o remount,rw "$OPT_MOUNT" 2>/dev/null || true; fi  # Restore rw
}

opt_rw_or_fail() { opt_rw || fail "$1" "Cannot remount ${OPT_MOUNT} rw"; }  # Helper: remount or fail at step

fail() {  # S7/S17: fatal error handler (must print plain text to STDOUT and exit)
  local step="$1"; shift  # First arg is step label (e.g., S3)
  echo "FAILED ${step}-${HOST_SHORT} $(date +%Y%m%d-%H:%M): $*"  # Required failure format (S17)
  exit 1  # Stop immediately on fatal conditions (S7)
}

#======================================================
# S8: Soft-fail handling (warn + continue)
#======================================================

WARNLOG=""  # Set after TMPDIR is created; warnings are also appended to this file (S8)
S8_HAD_ERROR=0  # Track whether any warnings occurred (S8)

warn() {  # S8: warning logger (does NOT exit)
  local msg="$1"  # Warning text
  S8_HAD_ERROR=1  # Ensure we bundle errors at cleanup time (S8)
  echo "WARN S8 - $HOST_SHORT $(date +%Y%m%d-%H:%M): $msg"  # Plain text warning to STDOUT (S8)
  [ -n "${WARNLOG:-}" ] && echo "WARN S8 - $HOST_SHORT $(date +%Y%m%d-%H:%M): $msg" >> "$WARNLOG" 2>/dev/null || true  # Append to error.log
}

bundle_errors() {  # S8: bundle working directory into /opt/security/errors/error-YYYYMMDD.tgz
  [ "${S8_HAD_ERROR:-0}" -eq 1 ] || return 0  # Only bundle if at least one warning happened
  [ -n "${TMPDIR:-}" ] || return 0  # Only bundle if TMPDIR is known
  [ -d "$TMPDIR" ] || return 0  # Only bundle if TMPDIR exists

  local BUNDLE="${ERR_BASE}/error-${TODAY}.tgz"  # Required error archive name (S8)

  opt_rw || return 0  # Need /opt writable to store the bundle (K1)
  mkdir -p "$ERR_BASE" 2>/dev/null || true  # Ensure errors directory exists (S8)
  tar -czf "$BUNDLE" -C "$TMPDIR" . 2>/dev/null || true  # Bundle entire TMPDIR contents (S8)
  restore_opt  # Restore /opt to its original mode (K12)
}

cleanup() {  # K12/S19: always restore system state and preserve required artifacts
  bundle_errors 2>/dev/null || true  # If warnings occurred, preserve TMPDIR bundle (S8)
  restore_opt  # Always restore /opt mount mode at exit (K12)
}

trap cleanup EXIT INT TERM  # Ensure cleanup runs for normal exit or interruption (K12/S19)

#======================================================
# S1: Working directory
#======================================================

[ "$EUID" -eq 0 ] || fail "S1" "Must run as root (use sudo)"  # Script needs /opt remount; must be root (S1/K1)
TODAY="$(date +%Y%m%d)"  # Date used for working directory and validation (S1/S5)
TMPDIR="${TMP_BASE}/${TODAY}"  # Required working directory path (S1)

opt_rw_or_fail "S1"  # Remount /opt rw to create working directory (K1)
mkdir -p "$TMPDIR" || fail "S1" "Cannot create TMPDIR ($TMPDIR)"  # Create /opt/security/tmp/YYYYMMDD (S1)
WARNLOG="${TMPDIR}/error.log"  # Local warning log file (S8)
restore_opt  # Return /opt to original mode ASAP (K12)

#======================================================
# S2: Parse parameters (-d -r -u)
#======================================================

url=""; region=""; userid=""  # Initialise required parameters (S2)
while getopts "d:r:u:" option; do  # Accept parameters in any order (S2)
  case "$option" in
    d) url="$OPTARG" ;;  # Base HTTPS URL for downloads (K2/S3)
    r) region="$OPTARG" ;;  # Region used in URL path and upload host naming (K5/K9)
    u) userid="$OPTARG" ;;  # Upload user (K10/S14)
    *) fail "S2" "Invalid option or missing value (-d -r -u required)" ;;  # Reject invalid args (S2)
  esac
done

[ -n "$url" ]    || fail "S2" "Missing -d base URL"  # -d is required (S2)
[ -n "$region" ] || fail "S2" "Missing -r region"  # -r is required (S2)
[ -n "$userid" ] || fail "S2" "Missing -u userid"  # -u is required (S2)

case "$url" in
  https://*) ;;  # Must be HTTPS (K2)
  *) fail "S2" "Base URL must start with https://" ;;  # Reject http or other schemes (K2)
esac

#======================================================
# S3: Download data file + signature (K4-K6)
#======================================================

FQDN="$(hostname -f)"  # Fully qualified domain name (K4)
SERVERID="$(printf "%s" "$FQDN" | md5sum | awk '{print $1}')"  # serverid = md5(FQDN) (K4)

DATAURL="${url}/${region}/${TODAY}/${SERVERID}.dat"  # Download path: /region/YYYYMMDD/serverid.dat (K5)
SIGURL="${url}/${region}/${TODAY}/${SERVERID}.dat.gpg"  # Signature path: same + .gpg (K6)

opt_rw_or_fail "S3"  # Remount /opt rw to store downloaded files (K1)
curl -f -s -o "$TMPDIR/${SERVERID}.dat"     "$DATAURL" || fail "S3" "Failed to download data file"  # Fetch .dat (S3)
curl -f -s -o "$TMPDIR/${SERVERID}.dat.gpg" "$SIGURL"  || fail "S3" "Failed to download signature"  # Fetch .dat.gpg (S3)
restore_opt  # Restore /opt mode after downloads (K12)
echo "S3 done: Download OK"  # Minimal success message (plain text)

#======================================================
# S4: Verify signature of the downloaded data file
#======================================================

gpg --verify "$TMPDIR/${SERVERID}.dat.gpg" "$TMPDIR/${SERVERID}.dat" >/dev/null 2>&1 || fail "S4" "Signature verification failed"  # Verify integrity/authenticity (S4)
echo "S4 done: Data file integrity OK"  # Minimal success message

#======================================================
# S5: Validate datestamp inside data file
#======================================================

FILE_DATE="$(grep -v '^[[:space:]]*#' "$TMPDIR/${SERVERID}.dat" | sed '/^[[:space:]]*$/d' | head -n 1)"  # First non-comment line (S5)
[ "$FILE_DATE" = "$TODAY" ] || fail "S5" "Datestamp mismatch"  # Must match local date + filename date (S5)
echo "S5 done: Datestamp OK"  # Minimal success message

#======================================================
# S6: Validate tool hashes for validate + sectar/backtool
#======================================================

DATA="$TMPDIR/${SERVERID}.dat"  # Local data file path (S6)
VAL="$VAL_TOOL"  # validate tool path (S6)
SEC="$SEC_TOOL"  # sectar tool path (S6)

VEXP="$(awk '$1=="VALIDATE"{print $2}' "$DATA")" || fail "S6" "Missing VALIDATE hash"  # Expected validate hash from .dat (S6)
SEXP="$(awk '$1=="BACKTOOL"{print $2}' "$DATA" || awk '$1=="SECTAR"{print $2}' "$DATA")" || fail "S6" "Missing SECTAR hash"  # Expected sectar/backtool hash (S6)

[ -x "$VAL" ] || fail "S6" "validate tool missing"  # Ensure validate exists and executable (S6)
[ -x "$SEC" ] || fail "S6" "sectar tool missing"  # Ensure sectar exists and executable (S6)

VACT="$("$VAL" "$VAL" | awk '{print $1}')"  # Compute validate hash using validate itself (S6)
SACT="$("$VAL" "$SEC" | awk '{print $1}')"  # Compute sectar hash using validate (S6)

[ "$VACT" = "$VEXP" ] || fail "S6" "validate hash mismatch"  # Detect tampering/rootkits (S6)
[ "$SACT" = "$SEXP" ] || fail "S6" "sectar hash mismatch"  # Detect tampering/rootkits (S6)
echo "S6 done: validate + sectar/backtool OK"  # Minimal success message

#======================================================
# S9: Process BKT backup targets (and build backup.list)
#======================================================

BACKUP_LIST="$TMPDIR/backup.list"  # List of files/dirs to back up (S9/S10)
opt_rw_or_fail "S9"  # Need /opt rw to create backup.list (K1)
: > "$BACKUP_LIST"  # Truncate/create the backup list file (S9)
restore_opt  # Restore /opt mode after file creation (K12)

awk '$1=="BKT"{print $2}' "$DATA" | while read -r TARGET; do  # Read each BKT path from the .dat file (S9)
  if [ -e "$TARGET" ]; then  # Only include targets that exist (S9)
    echo "$TARGET" >> "$BACKUP_LIST"  # Append target path to backup.list (S9)
  fi
done
echo "S9 done"  # Minimal success message

#======================================================
# S10: Create backup tar archive from backup.list using sectar
#======================================================

BACKUP_FILE="$(hostname -s)-config-${TODAY}.tar"  # Required backup file naming convention (S10)
BACKUP_PATH="$TMPDIR/$BACKUP_FILE"  # Full path to backup tar (S10)

if [ -s "$BACKUP_LIST" ]; then  # Only create backup if list is not empty (S10)
  opt_rw_or_fail "S10"  # Remount /opt rw for writing archive (K1)
  "$SEC" -cf "$BACKUP_PATH" -T "$BACKUP_LIST" || warn "S10: Backup failed"  # Create tar using sectar (S10)
  restore_opt  # Restore /opt mode (K12)
  echo "S10 done: Backup created"  # Minimal success message
fi

#======================================================
# S11 + S12: Create system report (stored under TMPDIR)
#======================================================

REPORT="$TMPDIR/validation-${TODAY}.txt"  # Report file name (S12)
opt_rw_or_fail "S11"  # Need /opt rw to write report (K1)
: > "$REPORT"  # Truncate/create report file (S12)
ss -tuln >> "$REPORT"  # Record listening sockets (S11a)
df -BM >> "$REPORT"  # Record disk usage in MB (supports S11e reporting)
restore_opt  # Restore /opt mode (K12)
echo "S11/S12 done"  # Minimal success message

#======================================================
# S13: Package all outputs and sign the archive (non-interactive)
#======================================================

DATESTAMP="$(date +%Y%m%d)"  # Date used in archive file name (S13)
ARCHIVE="$TMPDIR/${SERVERID}-validate-${DATESTAMP}.tgz"  # Required name: serverid-validate-yyyymmdd.tgz (S13)
SIGFILE="${ARCHIVE}.sig"  # Detached signature must be created for the archive (S13)

tar -czf "$ARCHIVE" -C "$TMPDIR" .  # Create compressed bundle containing backup + report + other outputs (S13)
gpg --batch --yes --pinentry-mode loopback --passphrase-file "$PASSFILE" --local-user "$GPG_USER" --detach-sign -o "$SIGFILE" "$ARCHIVE" 2>/dev/null || true  # Sign without user input (S13/S18)

[ -f "$SIGFILE" ] || fail "S13" "Signing failed"  # Fail if signature was not produced (S13)
echo "S13 done"  # Minimal success message

#======================================================
# S14 + S15 + S16: Upload, remote verification, final output lines
#======================================================

UPLOAD_SERVER="backup.${region}.int.org"  # Upload host naming rule: backup.<region>.int.org (S14/K9)
SSH_KEY="${SEC_BASE}/${userid}.id"  # SSH private key path is based on userid (K10)
REMOTE_DIR="${SUBMIT_BASE}/${SERVERID}/$(date +%Y)/$(date +%m)"  # Remote path: /submission/serverid/YYYY/MM (S14)

ssh -i "$SSH_KEY" -p "$SSH_PORT" "$userid@$UPLOAD_SERVER" "mkdir -p '$REMOTE_DIR'" || fail "S14" "mkdir failed"  # Ensure remote directory exists (S14)
scp -i "$SSH_KEY" -P "$SSH_PORT" "$ARCHIVE" "$SIGFILE" "$userid@$UPLOAD_SERVER:$REMOTE_DIR/" || fail "S14" "scp failed"  # Upload tgz + sig (S14)

ssh -i "$SSH_KEY" -p "$SSH_PORT" "$userid@$UPLOAD_SERVER" "cd '$REMOTE_DIR' && gpg --verify '$SIGFILE' '$ARCHIVE'" || fail "S15" "verify failed"  # Remote verification (S15)

bytes="$(stat -c '%s' "$ARCHIVE")"  # Size in bytes for final UPLOAD line (S16)
size_mb="$(( (bytes + 1048575) / 1048576 ))"  # Convert to MB (rounded up) (S16)
sha="$(sha256sum "$ARCHIVE" | awk '{print $1}')"  # sha256 checksum of the uploaded archive (S16)

echo "UPLOAD $(basename "$ARCHIVE") ${size_mb}MB ${sha}"  # Required UPLOAD output line (S16)
echo "VALIDATE datafile Check for ${HOST_SHORT} $(date +%Y%m%d-%H:%M) OK"  # Required final OK output line (S16)

echo "S16 finished successfully"  # Final status message (plain text)
exit 0  # Successful exit (S16)
