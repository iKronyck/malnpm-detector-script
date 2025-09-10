#!/usr/bin/env bash
  # detect_malicious_npm.sh
  # Detects compromised versions in npm, yarn, and pnpm lockfiles
  # Improved version with better error handling and more accurate detection

  set -euo pipefail

  # Colors for output
  RED='\033[0;31m'
  GREEN='\033[0;32m'
  YELLOW='\033[1;33m'
  NC='\033[0m' # No Color

  # List of known malicious packages and versions (updated)
  MALICIOUS_PACKAGES=(
      "debug@4.4.2"
      "chalk@5.6.1"
      "ansi-styles@6.2.2"
      "ansi-regex@6.2.1"
      "strip-ansi@7.1.1"
      "supports-color@10.2.1"
      "wrap-ansi@9.0.1"
      "slice-ansi@7.1.1"
      "color@5.0.1"
      "color-convert@3.1.1"
      "color-string@2.1.1"
      "color-name@2.0.1"
      "is-arrayish@0.3.3"
      "simple-swizzle@0.2.3"
      "error-ex@1.3.3"
      "has-ansi@6.0.1"
      "chalk-template@1.1.1"
      "backslash@0.2.1"
  )

  # Output files
  OUTPUT="malicious_packages_report.csv"
  LOG_FILE="scan_$(date +%Y%m%d_%H%M%S).log"

  # Logging function
  log() {
      echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
  }

  # Show usage/help
  show_usage() {
      echo "Usage: $0 [DIRECTORY]"
      echo "If no directory is specified, the current one (.) is used"
      echo ""
      echo "Options:"
      echo "  -h, --help    Show this help"
      echo "  -v, --verbose Verbose output"
  }

  # Process arguments
  VERBOSE=false
  SCAN_DIR="."

  while [[ $# -gt 0 ]]; do
      case $1 in
          -h|--help)
              show_usage
              exit 0
              ;;
          -v|--verbose)
              VERBOSE=true
              shift
              ;;
          -*)
              echo "Unknown option: $1" >&2
              show_usage
              exit 1
              ;;
          *)
              SCAN_DIR="$1"
              shift
              ;;
      esac
  done

  # Validate directory
  if [[ ! -d "$SCAN_DIR" ]]; then
      echo -e "${RED}Error: Directory '$SCAN_DIR' does not exist${NC}" >&2
      exit 1
  fi

  # Initialize output files
  echo "timestamp,file,package,version,lockfile_type" > "$OUTPUT"

  log "Starting scan in directory: $SCAN_DIR"
  log "Looking for ${#MALICIOUS_PACKAGES[@]} known malicious packages"

  # Counters
  TOTAL_LOCKFILES=0
  MALICIOUS_FOUND=0

  # Check for package in package-lock.json
  check_package_lock() {
      local file="$1"
      local pkg="$2"
      local ver="$3"

      # Search with jq if available, otherwise fallback to grep
      if command -v jq >/dev/null 2>&1; then
          if jq -e --arg pkg "$pkg" --arg ver "$ver" '
              .packages | to_entries[] | 
              select(.key | test("node_modules/" + $pkg + "$")) | 
              select(.value.version == $ver)
          ' "$file" >/dev/null 2>&1; then
              return 0
          fi
      else
          # Grep fallback with more precision
          if grep -q "\"node_modules/$pkg\"" "$file" && \
             grep -A5 "\"node_modules/$pkg\"" "$file" | grep -q "\"version\": \"$ver\""; then
              return 0
          fi
      fi
      return 1
  }

  # Check for package in yarn.lock
  check_yarn_lock() {
      local file="$1"
      local pkg="$2"
      local ver="$3"

      # Search with a more specific pattern in yarn.lock
      if grep -qE "^\"?$pkg@.*\"?:$" "$file"; then
          local section=$(awk "/^\"?$pkg@.*\"?:$/,/^$/" "$file")
          if echo "$section" | grep -q "version \"$ver\""; then
              return 0
          fi
      fi
      return 1
  }

  # Check for package in pnpm-lock.yaml
  check_pnpm_lock() {
      local file="$1"
      local pkg="$2"
      local ver="$3"

      # Check in dependencies and devDependencies
      if grep -qE "^\s*$pkg@$ver:" "$file" || \
         grep -qE "^\s*/$pkg@$ver:" "$file"; then
          return 0
      fi
      return 1
  }

  # Search lockfiles and analyze them
  while IFS= read -r -d '' lockfile; do
      TOTAL_LOCKFILES=$((TOTAL_LOCKFILES + 1))

      if [[ "$VERBOSE" == true ]]; then
          log "Analyzing: $lockfile"
      fi

      lockfile_type=""
      case "$lockfile" in
          *package-lock.json) lockfile_type="npm" ;;
          *yarn.lock) lockfile_type="yarn" ;;
          *pnpm-lock.yaml) lockfile_type="pnpm" ;;
      esac

      for package_version in "${MALICIOUS_PACKAGES[@]}"; do
          IFS='@' read -r pkg ver <<< "$package_version"

          found=false
          case "$lockfile_type" in
              npm)
                  if check_package_lock "$lockfile" "$pkg" "$ver"; then
                      found=true
                  fi
                  ;;
              yarn)
                  if check_yarn_lock "$lockfile" "$pkg" "$ver"; then
                      found=true
                  fi
                  ;;
              pnpm)
                  if check_pnpm_lock "$lockfile" "$pkg" "$ver"; then
                      found=true
                  fi
                  ;;
          esac

          if [[ "$found" == true ]]; then
              MALICIOUS_FOUND=$((MALICIOUS_FOUND + 1))
              timestamp=$(date '+%Y-%m-%d %H:%M:%S')
              echo "$timestamp,\"$lockfile\",\"$pkg\",\"$ver\",\"$lockfile_type\"" >> "$OUTPUT"
              echo -e "${RED}⚠️  FOUND: $pkg@$ver in $lockfile${NC}"
              log "MALICIOUS DETECTED: $pkg@$ver in $lockfile"
          fi
      done

  done < <(find "$SCAN_DIR" -type f \( -name "package-lock.json" -o -name "yarn.lock" -o -name "pnpm-lock.yaml" \) -print0)

  # Final summary
  echo ""
  echo "📊 SCAN SUMMARY:"
  echo "─────────────────────"
  echo "🔍 Lockfiles analyzed: $TOTAL_LOCKFILES"
  echo "⚠️  Malicious packages found: $MALICIOUS_FOUND"

  if [[ $MALICIOUS_FOUND -gt 0 ]]; then
      echo -e "${RED}🚨 MALICIOUS PACKAGES DETECTED${NC}"
      echo -e "${YELLOW}📄 Check the detailed report at: $OUTPUT${NC}"
      echo -e "${YELLOW}📋 Full log at: $LOG_FILE${NC}"
      echo ""
      echo "🔧 RECOMMENDED ACTIONS:"
      echo "1. Update the affected packages immediately"
      echo "2. Review your code for suspicious behavior"
      echo "3. Rotate credentials if they may have been compromised"
      exit 1
  else
      echo -e "${GREEN}✅ No known malicious packages found${NC}"
      log "Scan completed - No threats found"
      exit 0
  fi
