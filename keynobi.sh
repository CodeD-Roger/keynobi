#!/bin/bash

# ANSI color codes
RED="\033[0;31m"
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
BLUE="\033[0;34m"
MAGENTA="\033[0;35m"
CYAN="\033[0;36m"
BOLD="\033[1m"
RESET="\033[0m"

# Print colored header
print_header() {
  local title="$1"
  local len=$(echo -n "$title" | wc -c)
  echo -e "${BOLD}${BLUE}$title${RESET}"
  echo -e "${CYAN}$(printf '=%.0s' $(seq 1 "$len"))${RESET}"
}

# Print colored section
print_section() {
  local title="$1"
  local len=$(echo -n "$title" | wc -c)
  echo -e "${BOLD}${GREEN}$title${RESET}"
printf "${YELLOW}"; printf -- '-%.0s' $(seq 1 "$len"); printf "${RESET}\n"
}

# Print error message
print_error() {
  echo -e "${RED}$1${RESET}"
}

# Print info message
print_info() {
  echo -e "${CYAN}$1${RESET}"
}

# Print success message
print_success() {
  echo -e "${GREEN}$1${RESET}"
}

# Check if required tools are installed
check_requirements() {
  local missing_tools=()
  
  # Check for OpenSSL
  if ! command -v openssl &> /dev/null; then
    missing_tools+=("openssl")
  fi
  
  # Check for GPG
  if ! command -v gpg &> /dev/null; then
    missing_tools+=("gpg")
  fi
  
  # Check for SSH tools
  if ! command -v ssh-keygen &> /dev/null; then
    missing_tools+=("ssh-keygen")
  fi
  
  # Report missing tools
  if [ ${#missing_tools[@]} -gt 0 ]; then
    print_error "Missing required tools: ${missing_tools[*]}"
    print_info "Please install them before running this script."
    exit 1
  fi
}

# Temporary files to store scan results
SSL_FILES="/tmp/ssl_files.txt"
SSL_FILTERED_FILES="/tmp/ssl_filtered_files.txt"  # New file for filtered SSL certificates
SSH_FILES="/tmp/ssh_files.txt"
PGP_FILES="/tmp/pgp_files.txt"
ALL_CERTS="/tmp/all_certs.txt"
PASSPHRASE_ERRORS="/tmp/passphrase_errors.txt"  # New file to track passphrase errors

# Clean up temporary files
cleanup() {
  rm -f "$SSL_FILES" "$SSL_FILTERED_FILES" "$SSH_FILES" "$PGP_FILES" "$ALL_CERTS" "$PASSPHRASE_ERRORS"
}

# Trap for cleanup on exit
trap cleanup EXIT

# SSL/TLS certificate filter options
SSL_FILTER_ENABLED=false
SSL_FILTER_DOMAIN=""
SSL_FILTER_ISSUER=""
SSL_FILTER_EXPIRY_DAYS=0

# Function to prompt for SSL/TLS filter options
configure_ssl_filter() {
  print_header "Configure SSL/TLS Certificate Filter"
  
  read -p "Enable filtering? (y/n): " enable_filter
  if [[ "$enable_filter" == "y" || "$enable_filter" == "Y" ]]; then
    SSL_FILTER_ENABLED=true
    
    read -p "Filter by domain (leave empty to skip): " SSL_FILTER_DOMAIN
    read -p "Filter by issuer (leave empty to skip): " SSL_FILTER_ISSUER
    read -p "Show only certificates expiring within days (0 to skip): " SSL_FILTER_EXPIRY_DAYS
    
    print_success "Filter configured!"
  else
    print_info "Filtering disabled."
  fi
}

# Apply SSL/TLS certificate filters
apply_ssl_filter() {
  if [ "$SSL_FILTER_ENABLED" = false ]; then
    # If filtering is disabled, use all SSL files
    cp "$SSL_FILES" "$SSL_FILTERED_FILES"
    return
  fi
  
  print_info "Applying SSL/TLS certificate filters..."
  > "$SSL_FILTERED_FILES"
  
  while IFS= read -r file; do
    local include=true
    
    # Filter by domain (subject)
    if [ -n "$SSL_FILTER_DOMAIN" ]; then
      if ! openssl x509 -in "$file" -noout -subject 2>/dev/null | grep -i "$SSL_FILTER_DOMAIN" > /dev/null; then
        include=false
      fi
    fi
    
    # Filter by issuer
    if [ "$include" = true ] && [ -n "$SSL_FILTER_ISSUER" ]; then
      if ! openssl x509 -in "$file" -noout -issuer 2>/dev/null | grep -i "$SSL_FILTER_ISSUER" > /dev/null; then
        include=false
      fi
    fi
    
    # Filter by expiry
    if [ "$include" = true ] && [ "$SSL_FILTER_EXPIRY_DAYS" -gt 0 ]; then
      if ! openssl x509 -in "$file" -noout -checkend $(( 86400 * SSL_FILTER_EXPIRY_DAYS )) &>/dev/null; then
        # Certificate will expire within the specified days
        include=true
      else
        include=false
      fi
    fi
    
    # Include the certificate if it passes all filters
    if [ "$include" = true ]; then
      echo "$file" >> "$SSL_FILTERED_FILES"
    fi
  done < "$SSL_FILES"
  
  local filtered_count=$(wc -l < "$SSL_FILTERED_FILES")
  local total_count=$(wc -l < "$SSL_FILES")
  
print_success "$filtered_count certificates match the filters (out of $total_count scanned)"
}

# Scan for certificates
scan_certificates() {
  print_header "Scanning for certificates..."
  
  # Create empty files
  > "$SSL_FILES"
  > "$SSL_FILTERED_FILES"
  > "$SSH_FILES"
  > "$PGP_FILES"
  > "$ALL_CERTS"
  > "$PASSPHRASE_ERRORS"
  
  # Directories to exclude from scanning
  EXCLUDE_DIRS="-path /proc -o -path /sys -o -path /dev -o -path /run -o -path /tmp -o -path /var/tmp -o -path /var/cache"
  
  print_info "Scanning for SSL/TLS certificates..."
find / -type f \( -name "*.crt" -o -name "*.pem" -o -name "*.cer" -o -name "*.key" -o -name "*.p12" \) \
  ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" ! -path "/tmp/*" ! -path "/var/tmp/*" ! -path "/var/cache/*" \
  2>/dev/null | while read -r file; do
    # Check if it's a certificate file
    if openssl x509 -in "$file" -noout &>/dev/null; then
      echo "$file" >> "$SSL_FILES"
      echo "SSL:$file" >> "$ALL_CERTS"
    # Check for PKCS#12 files that might require a passphrase
    elif [[ "$file" == *".p12" ]] || [[ "$file" == *".pfx" ]]; then
      # Try with empty passphrase first
      if ! openssl pkcs12 -in "$file" -nokeys -noout -passin pass: &>/dev/null; then
        # If it fails, it might need a passphrase
        echo "$file" >> "$PASSPHRASE_ERRORS"
        print_error "Certificate $file requires a passphrase and couldn't be processed."
      else
        echo "$file" >> "$SSL_FILES"
        echo "SSL:$file" >> "$ALL_CERTS"
      fi
    fi
done

  
  print_info "Scanning for SSH keys..."
find / -type f \( -name "id_rsa" -o -name "id_ecdsa" -o -name "id_ed25519" -o -name "*.pub" -o -path "*/.ssh/*" \) \
  ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" ! -path "/tmp/*" ! -path "/var/tmp/*" ! -path "/var/cache/*" \
  $$ ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" ! -path "/tmp/*" ! -path "/var/tmp/*" ! -path "/var/cache/*" $$ \
  2>/dev/null | while read -r file; do
    # Try to read the SSH key
    if ssh-keygen -l -f "$file" &>/dev/null; then
      echo "$file" >> "$SSH_FILES"
      echo "SSH:$file" >> "$ALL_CERTS"
    elif [[ "$file" != *".pub" ]] && ! [[ -d "$file" ]]; then
      # Check if it's a private key that might need a passphrase
      if ssh-keygen -y -f "$file" -P "" &>/dev/null; then
        echo "$file" >> "$SSH_FILES"
        echo "SSH:$file" >> "$ALL_CERTS"
      else
        echo "$file" >> "$PASSPHRASE_ERRORS"
        print_error "SSH key $file requires a passphrase and couldn't be processed."
      fi
    fi
done
  
  print_info "Scanning for PGP keys..."
find / -type f \( -name "*.gpg" -o -name "*.asc" -o -name "*.pgp" -o -name "*.key" \) \
  ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" ! -path "/tmp/*" ! -path "/var/tmp/*" ! -path "/var/cache/*" \
  $$ ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" ! -path "/tmp/*" ! -path "/var/tmp/*" ! -path "/var/cache/*" $$ \
  2>/dev/null | while read -r file; do
    # Try to read the PGP key
    if gpg --list-packets "$file" &>/dev/null || file "$file" | grep -q "PGP"; then
      echo "$file" >> "$PGP_FILES"
      echo "PGP:$file" >> "$ALL_CERTS"
    elif gpg --list-packets "$file" 2>&1 | grep -q "passphrase"; then
      echo "$file" >> "$PASSPHRASE_ERRORS"
      print_error "PGP key $file requires a passphrase and couldn't be processed."
    fi
done
  
  # Apply SSL/TLS filters if configured
  apply_ssl_filter
  
  # Count found certificates
  SSL_COUNT=$(wc -l < "$SSL_FILES")
  SSL_FILTERED_COUNT=$(wc -l < "$SSL_FILTERED_FILES")
  SSH_COUNT=$(wc -l < "$SSH_FILES")
  PGP_COUNT=$(wc -l < "$PGP_FILES")
  PASSPHRASE_ERROR_COUNT=$(wc -l < "$PASSPHRASE_ERRORS")
  
  print_success "Scan completed!"
  echo -e "${BOLD}Found:${RESET}"
  echo -e "  ${YELLOW}SSL/TLS Certificates:${RESET} $SSL_COUNT (Filtered: $SSL_FILTERED_COUNT)"
  echo -e "  ${YELLOW}SSH Keys:${RESET} $SSH_COUNT"
  echo -e "  ${YELLOW}PGP Keys:${RESET} $PGP_COUNT"
  
  if [ "$PASSPHRASE_ERROR_COUNT" -gt 0 ]; then
    print_error "Files requiring passphrase: $PASSPHRASE_ERROR_COUNT"
    echo -e "${YELLOW}Note:${RESET} Some files couldn't be processed because they require a passphrase."
    echo -e "      Check $PASSPHRASE_ERRORS for the list of these files."
  fi
}

# Display SSL/TLS certificate information
display_ssl_info() {
  local file="$1"
  
  echo -e "${BOLD}${MAGENTA}Certificate:${RESET} $(basename "$file")"
  echo -e "${YELLOW}Path:${RESET} $file"
  
  # Extract certificate information
  local subject
  local issuer
  local valid_from
  local valid_to
  local fingerprint
  
  subject=$(openssl x509 -in "$file" -noout -subject 2>/dev/null | sed 's/subject=//g')
  issuer=$(openssl x509 -in "$file" -noout -issuer 2>/dev/null | sed 's/issuer=//g')
  valid_from=$(openssl x509 -in "$file" -noout -startdate 2>/dev/null | sed 's/notBefore=//g')
  valid_to=$(openssl x509 -in "$file" -noout -enddate 2>/dev/null | sed 's/notAfter=//g')
  fingerprint=$(openssl x509 -in "$file" -noout -fingerprint -sha256 2>/dev/null)
  
  echo -e "${YELLOW}Subject:${RESET} $subject"
  echo -e "${YELLOW}Issuer:${RESET} $issuer"
  echo -e "${YELLOW}Valid From:${RESET} $valid_from"
  echo -e "${YELLOW}Valid To:${RESET} $valid_to"
  echo -e "${YELLOW}Fingerprint:${RESET} $fingerprint"
  
  # Check if certificate is expired
  if openssl x509 -in "$file" -noout -checkend 0 &>/dev/null; then
    echo -e "${GREEN}Status: Valid${RESET}"
  else
    echo -e "${RED}Status: Expired${RESET}"
  fi
  
  echo
}

# Display SSH key information
display_ssh_info() {
  local file="$1"
  
  echo -e "${BOLD}${MAGENTA}SSH Key:${RESET} $(basename "$file")"
  echo -e "${YELLOW}Path:${RESET} $file"
  
  # Extract SSH key information
  local key_info
  key_info=$(ssh-keygen -l -f "$file" 2>/dev/null)
  
  if [ $? -eq 0 ]; then
    local bits
    local fingerprint
    local type
    
    bits=$(echo "$key_info" | awk '{print $1}')
    fingerprint=$(echo "$key_info" | awk '{print $2}')
    type=$(echo "$key_info" | awk '{print $4}' | sed 's/(//g' | sed 's/)//g')
    
    echo -e "${YELLOW}Type:${RESET} $type"
    echo -e "${YELLOW}Bits:${RESET} $bits"
    echo -e "${YELLOW}Fingerprint:${RESET} $fingerprint"
    
    # Check if it's a private or public key
    if [[ "$file" == *".pub" ]]; then
      echo -e "${YELLOW}Key Type:${RESET} Public Key"
    else
      echo -e "${YELLOW}Key Type:${RESET} Private Key"
      
      # Check permissions for private keys
      local perms
      perms=$(stat -c "%a" "$file")
      if [ "$perms" != "600" ] && [ "$perms" != "400" ]; then
        echo -e "${RED}Warning: Insecure permissions ($perms). Should be 600 or 400.${RESET}"
      else
        echo -e "${GREEN}Permissions: $perms (Secure)${RESET}"
      fi
    fi
  else
    echo -e "${RED}Error: Could not read SSH key information${RESET}"
  fi
  
  echo
}

# Display PGP key information
display_pgp_info() {
  local file="$1"
  
  echo -e "${BOLD}${MAGENTA}PGP Key:${RESET} $(basename "$file")"
  echo -e "${YELLOW}Path:${RESET} $file"
  
  # Try to extract PGP key information
  if gpg --list-packets "$file" &>/dev/null; then
    # Get key information
    local key_info
    key_info=$(gpg --list-packets "$file" 2>/dev/null)
    
    # Extract key type
    local key_type
    key_type=$(echo "$key_info" | grep -o "public key" | head -1)
    if [ -z "$key_type" ]; then
      key_type=$(echo "$key_info" | grep -o "secret key" | head -1)
    fi
    if [ -z "$key_type" ]; then
      key_type="unknown"
    fi
    
    echo -e "${YELLOW}Key Type:${RESET} $key_type"
    
    # Try to import and show key info (temporary)
    local gpg_info
    gpg_info=$(gpg --import --import-options show-only "$file" 2>/dev/null)
    
    if [ $? -eq 0 ]; then
      # Extract UID if available
      local uid
      uid=$(echo "$gpg_info" | grep "uid" | head -1 | sed 's/uid//g' | xargs)
      if [ -n "$uid" ]; then
        echo -e "${YELLOW}UID:${RESET} $uid"
      fi
      
      # Extract key ID if available
      local key_id
      key_id=$(echo "$gpg_info" | grep -o "key [A-F0-9]\{8,16\}" | head -1 | awk '{print $2}')
      if [ -n "$key_id" ]; then
        echo -e "${YELLOW}Key ID:${RESET} $key_id"
      fi
    else
      echo -e "${YELLOW}Note:${RESET} Limited information available (cannot import key)"
    fi
  else
    echo -e "${RED}Error: Could not read PGP key information${RESET}"
  fi
  
  echo
}

# Display directories containing certificates of a specific type
display_directories() {
  local cert_type="$1"
  local file_list="$2"
  
  if [ ! -s "$file_list" ]; then
    print_error "No $cert_type certificates found."
    return
  fi
  
  print_section "Directories containing $cert_type certificates:"
  
  # Get unique directories
  local dirs
  dirs=$(dirname $(cat "$file_list") | sort | uniq)
  
  # Display directories with count
  local i=1
  while IFS= read -r dir; do
    local count
    count=$(grep -c "^$dir/" "$file_list")
    echo -e "$i. ${BOLD}$dir${RESET} ($count certificates)"
    ((i++))
  done <<< "$dirs"
  
  echo
}

# Display certificate details based on type
display_certificates() {
  local cert_type="$1"
  local file_list="$2"
  
  if [ ! -s "$file_list" ]; then
    print_error "No $cert_type certificates found."
    return
  fi
  
  print_section "$cert_type Certificate Details:"
  
  # Process each certificate
  while IFS= read -r file; do
    case "$cert_type" in
      "SSL/TLS")
        display_ssl_info "$file"
        ;;
      "SSH")
        display_ssh_info "$file"
        ;;
      "PGP")
        display_pgp_info "$file"
        ;;
    esac
  done < "$file_list"
}

# Display files that require a passphrase
display_passphrase_errors() {
  if [ ! -s "$PASSPHRASE_ERRORS" ]; then
    print_info "No files with passphrase issues found."
    return
  fi
  
  print_section "Files requiring a passphrase:"
  
  local i=1
  while IFS= read -r file; do
    echo -e "$i. ${BOLD}$file${RESET}"
    ((i++))
  done < "$PASSPHRASE_ERRORS"
  
  echo
}

# Interactive menu
show_menu() {
  local options=()
  local has_ssl=0
  local has_ssh=0
  local has_pgp=0
  local has_passphrase_errors=0
  
  # Check which certificate types were found
  if [ -s "$SSL_FILTERED_FILES" ]; then
    options+=("SSL/TLS")
    has_ssl=1
  fi
  
  if [ -s "$SSH_FILES" ]; then
    options+=("SSH")
    has_ssh=1
  fi
  
  if [ -s "$PGP_FILES" ]; then
    options+=("PGP")
    has_pgp=1
  fi
  
  if [ -s "$PASSPHRASE_ERRORS" ]; then
    options+=("Passphrase Errors")
    has_passphrase_errors=1
  fi
  
  # Add SSL filter option
  options+=("Configure SSL Filter")
  
  # Add "All" option if multiple types exist
  if [ ${#options[@]} -gt 1 ]; then
    options+=("All")
  fi
  
  options+=("Exit")
  
  # Display menu
  print_header "Certificate Explorer"
  echo -e "${BOLD}Which type of certificates would you like to explore?${RESET}"
  
  local i=1
  for opt in "${options[@]}"; do
    echo -e "$i) $opt"
    ((i++))
  done
  
  # Get user choice
  local choice
  read -p "Enter your choice [1-${#options[@]}]: " choice
  
  # Process choice
  case "${options[$choice-1]}" in
    "SSL/TLS")
      display_directories "SSL/TLS" "$SSL_FILTERED_FILES"
      display_certificates "SSL/TLS" "$SSL_FILTERED_FILES"
      ;;
    "SSH")
      display_directories "SSH" "$SSH_FILES"
      display_certificates "SSH" "$SSH_FILES"
      ;;
    "PGP")
      display_directories "PGP" "$PGP_FILES"
      display_certificates "PGP" "$PGP_FILES"
      ;;
    "Passphrase Errors")
      display_passphrase_errors
      ;;
    "Configure SSL Filter")
      configure_ssl_filter
      apply_ssl_filter
      show_menu
      ;;
    "All")
      if [ $has_ssl -eq 1 ]; then
        display_directories "SSL/TLS" "$SSL_FILTERED_FILES"
        display_certificates "SSL/TLS" "$SSL_FILTERED_FILES"
      fi
      
      if [ $has_ssh -eq 1 ]; then
        display_directories "SSH" "$SSH_FILES"
        display_certificates "SSH" "$SSH_FILES"
      fi
      
      if [ $has_pgp -eq 1 ]; then
        display_directories "PGP" "$PGP_FILES"
        display_certificates "PGP" "$PGP_FILES"
      fi
      
      if [ $has_passphrase_errors -eq 1 ]; then
        display_passphrase_errors
      fi
      ;;
    "Exit")
      print_info "Exiting..."
      exit 0
      ;;
    *)
      print_error "Invalid choice. Exiting."
      exit 1
      ;;
  esac
}

# Main function
main() {
  print_header "Certificate Scanner"
  
  # Check requirements
  check_requirements
  
  # Scan for certificates
  scan_certificates
  
  # Show interactive menu
  show_menu
}

# Run main function
main
