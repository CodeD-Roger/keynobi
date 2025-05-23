#!/bin/bash

# ANSI color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Temporary files
TEMP_SSL="/tmp/ssl_certs_$$.txt"
TEMP_SSH="/tmp/ssh_keys_$$.txt"
TEMP_PGP="/tmp/pgp_keys_$$.txt"
TEMP_ERRORS="/tmp/cert_errors_$$.txt"
TEMP_WEB_CERTS="/tmp/web_certs_$$.txt"
TEMP_SERVICES="/tmp/services_443_$$.txt"
TEMP_USED_CERTS="/tmp/used_certs_$$.txt"
TEMP_ALL_CERTS="/tmp/all_certs_$$.txt"
TEMP_AUDIT="/tmp/audit_summary_$$.txt"

# Ensure temporary files are cleaned up on exit
trap 'rm -f "$TEMP_SSL" "$TEMP_SSH" "$TEMP_PGP" "$TEMP_ERRORS" "$TEMP_WEB_CERTS" "$TEMP_SERVICES" "$TEMP_USED_CERTS" "$TEMP_ALL_CERTS" "$TEMP_AUDIT"' EXIT

# Display functions
display_title() {
  echo -e "${BLUE}====================${NC}"
  echo -e "${BLUE}$1${NC}"
  echo -e "${BLUE}====================${NC}"
}

display_info() {
  echo -e "${GREEN}[INFO]${NC} $1"
}

display_error() {
  echo -e "${RED}[ERROR]${NC} $1"
}

display_success() {
  echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Ask user for scan scope
ask_scan_scope() {
  echo -e "${YELLOW}Do you want to scan the entire system or a specific directory?${NC}"
  echo "1. Entire system"
  echo "2. Specific directory"
  read -p "Choice [1-2]: " scope_choice
  case $scope_choice in
    1)
      SCAN_DIR="/"
      ;;
    2)
      read -p "Enter the directory to scan (e.g., /tmp/test_certs_1744730773): " custom_dir
      if [ -d "$custom_dir" ]; then
        SCAN_DIR="$custom_dir"
      else
        display_error "Directory does not exist. Falling back to entire system scan."
        SCAN_DIR="/"
      fi
      ;;
    *)
      display_error "Invalid choice. Falling back to entire system scan."
      SCAN_DIR="/"
      ;;
  esac
}

# Filter SSL results (example: exclude expired or specific issuers)
filter_ssl_results() {
  local input_file="$1"
  local output_file="$2"
  cp "$input_file" "$output_file"
}

# Scan system for certificates and keys
scan_system() {
  display_title "System Scan"
  > "$TEMP_SSL"
  > "$TEMP_SSH"
  > "$TEMP_PGP"
  > "$TEMP_ERRORS"
  > "$TEMP_ALL_CERTS"

  # Define directories to exclude
  local exclude_paths="-not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' -not -path '/run/*'"

  # Scan SSL/TLS certificates
  display_info "Searching for SSL/TLS certificates..."
  find "$SCAN_DIR" -type f \( -name "*.crt" -o -name "*.pem" -o -name "*.cer" -o -name "*.p12" \) -not -name "key_*.pem" $exclude_paths 2>/dev/null | while IFS= read -r file; do
    if [[ "$file" == *.p12 ]]; then
      # Try to extract certificate from PKCS#12
      if openssl pkcs12 -in "$file" -nodes -nokeys -passin pass:"" | openssl x509 -noout >/dev/null 2>&1; then
        echo "$file" >> "$TEMP_SSL"
        echo "$file (PKCS#12)" >> "$TEMP_ALL_CERTS"
      else
        error_msg=$(openssl pkcs12 -in "$file" -nodes -nokeys -passin pass:"" 2>&1)
        echo "SSL: $file (invalid PKCS#12 format: $error_msg)" >> "$TEMP_ERRORS"
      fi
    elif openssl x509 -in "$file" -noout >/dev/null 2>&1; then
      echo "$file" >> "$TEMP_SSL"
      echo "$file (Certificate)" >> "$TEMP_ALL_CERTS"
    else
      error_msg=$(openssl x509 -in "$file" -noout 2>&1)
      echo "SSL: $file (invalid format: $error_msg)" >> "$TEMP_ERRORS"
    fi
  done

  # Scan SSH keys
  display_info "Searching for SSH keys..."
  find "$SCAN_DIR" -type f \( -name "id_*" -o -name "*.pub" \) $exclude_paths 2>/dev/null | while IFS= read -r file; do
    if [[ "$file" == *.pub ]]; then
      # Accept public keys directly
      echo "$file" >> "$TEMP_SSH"
    elif ssh-keygen -y -P "" -f "$file" >/dev/null 2>&1; then
      # Accept private keys if valid
      echo "$file" >> "$TEMP_SSH"
    else
      echo "SSH: $file (needs passphrase or invalid)" >> "$TEMP_ERRORS"
    fi
  done

  # Scan PGP keys
  display_info " searching for PGP keys..."
  find "$SCAN_DIR" -type f \( -name "*.gpg" -o -name "*.asc" \) $exclude_paths 2>/dev/null | while IFS= read -r file; do
    if gpg --list-packets "$file" >/dev/null 2>&1; then
      echo "$file" >> "$TEMP_PGP"
    else
      error_msg=$(gpg --list-packets "$file" 2>&1)
      echo "PGP: $file (invalid or encrypted: $error_msg)" >> "$TEMP_ERRORS"
    fi
  done

  # Apply SSL filters
  local TEMP_SSL_FILTERED="/tmp/ssl_filtered_$$.txt"
  filter_ssl_results "$TEMP_SSL" "$TEMP_SSL_FILTERED"
  mv "$TEMP_SSL_FILTERED" "$TEMP_SSL"

  # Summarize results
  local ssl_count=$(wc -l < "$TEMP_SSL")
  local ssh_count=$(wc -l < "$TEMP_SSH")
  local pgp_count=$(wc -l < "$TEMP_PGP")
  local error_count=$(wc -l < "$TEMP_ERRORS")

  display_success "Scan finished!"
  echo -e "${YELLOW}Results:${NC}"
  echo -e "  SSL/TLS: $ssl_count"
  echo -e "  SSH Keys: $ssh_count"
  echo -e "  PGP Keys: $pgp_count"
  if [ "$error_count" -gt 0 ]; then
    display_error "  Errors: $error_count (see $TEMP_ERRORS)"
  fi
}

# Scan web services for certificates
scan_web_services_certs() {
  display_title "Web Services Certificate Scan"
  > "$TEMP_WEB_CERTS"
  > "$TEMP_ERRORS"

  # Scan NGINX
  display_info "Scanning NGINX configurations..."
  nginx_conf="/etc/nginx/nginx.conf"
  nginx_sites="/etc/nginx/sites-enabled/*"
  if [ -f "$nginx_conf" ]; then
    grep -h "ssl_certificate[^_]" "$nginx_conf" $nginx_sites 2>/dev/null | grep -v "#" | while IFS= read -r line; do
      cert_file=$(echo "$line" | awk '{print $2}' | tr -d ';')
      if [ -f "$cert_file" ]; then
        echo "$cert_file" >> "$TEMP_WEB_CERTS"
      else
        echo "NGINX: $cert_file (file not found)" >> "$TEMP_ERRORS"
      fi
    done
  else
    display_info "No NGINX configuration found."
  fi

  # Scan Apache
  display_info "Scanning Apache configurations..."
  apache_conf="/etc/apache2/apache2.conf"
  apache_sites="/etc/apache2/sites-enabled/*"
  if [ -f "$apache_conf" ]; then
    grep -h "SSLCertificateFile" "$apache_conf" $apache_sites 2>/dev/null | grep -v "#" | while IFS= read -r line; do
      cert_file=$(echo "$line" | awk '{print $2}')
      if [ -f "$cert_file" ]; then
        echo "$cert_file" >> "$TEMP_WEB_CERTS"
      else
        echo "Apache: $cert_file (file not found)" >> "$TEMP_ERRORS"
      fi
    done
  else
    display_info "No Apache configuration found."
  fi

  # Scan Tomcat
  display_info "Scanning Tomcat configurations..."
  find / -type f -name "server.xml" 2>/dev/null | while IFS= read -r file; do
    grep -h "certificateKeystoreFile" "$file" 2>/dev/null | grep -v "<!--" | while IFS= read -r line; do
      cert_file=$(echo "$line" | grep -oP 'certificateKeystoreFile="\K[^"]+')
      if [ -f "$cert_file" ]; then
        echo "$cert_file" >> "$TEMP_WEB_CERTS"
      else
        echo "Tomcat: $cert_file (file not found)" >> "$TEMP_ERRORS"
      fi
    done
  done

  # Display results
  display_web_certs_details
}

# Display web services certificates details
display_web_certs_details() {
  display_title "Web Services Certificates Details"
  if [ -s "$TEMP_WEB_CERTS" ]; then
    sort -u "$TEMP_WEB_CERTS" | while IFS= read -r file; do
      echo -e "${YELLOW}Certificate:${NC} $(basename "$file")"
      echo -e "${YELLOW}Path:${NC} $file"
      subject="N/A"
      issuer="N/A"
      start_date="N/A"
      end_date="N/A"
      fingerprint="N/A"
      status="Unknown"
      if [[ "$file" == *.p12 ]]; then
        if cert_data=$(openssl pkcs12 -in "$file" -nodes -nokeys -passin pass:"" 2>/dev/null); then
          subject=$(echo "$cert_data" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//')
          issuer=$(echo "$cert_data" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//')
          start_date=$(echo "$cert_data" | openssl x509 -noout -startdate 2>/dev/null | sed 's/notBefore=//')
          end_date=$(echo "$cert_data" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
          fingerprint=$(echo "$cert_data" | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/SHA256 Fingerprint=//')
          if echo "$cert_data" | openssl x509 -noout -checkend 0 >/dev/null 2>&1; then
            status="Valid"
          else
            status="Expired"
          fi
        fi
      else
        subject=$(openssl x509 -in "$file" -noout -subject 2>/dev/null | sed 's/subject=//')
        issuer=$(openssl x509 -in "$file" -noout -issuer 2>/dev/null | sed 's/issuer=//')
        start_date=$(openssl x509 -in "$file" -noout -startdate 2>/dev/null | sed 's/notBefore=//')
        end_date=$(openssl x509 -in "$file" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
        fingerprint=$(openssl x509 -in "$file" -noout -fingerprint -sha256 2>/dev/null | sed 's/SHA256 Fingerprint=//')
        if openssl x509 -in "$file" -noout -checkend 0 >/dev/null 2>&1; then
          status="Valid"
        else
          status="Expired"
        fi
      fi
      echo -e "${YELLOW}Subject:${NC} ${subject:-N/A}"
      echo -e "${YELLOW}Issuer:${NC} ${issuer:-N/A}"
      echo -e "${YELLOW}Valid From:${NC} ${start_date:-N/A}"
      echo -e "${YELLOW}Valid To:${NC} ${end_date:-N/A}"
      echo -e "${YELLOW}Fingerprint:${NC} sha256 Fingerprint=${fingerprint:-N/A}"
      echo -e "${YELLOW}Status:${NC} $status"
      echo
    done
  else
    echo "No web service certificates found."
  fi
}

# Scan remote certificate
scan_remote_cert() {
  display_title "Remote Certificate Scan"
  read -p "Enter domain or IP address: " target
  read -p "Enter port [default 443]: " port
  port=${port:-443}

  display_info "Attempting to connect to $target:$port..."
  local temp_cert="/tmp/remote_cert_$$.pem"
  if timeout 10 openssl s_client -connect "$target:$port" -servername "$target" </dev/null 2>/dev/null | openssl x509 > "$temp_cert" 2>/dev/null; then
    display_success "Certificate retrieved!"
    echo -e "${YELLOW}Target:${NC} $target:$port"
    subject=$(openssl x509 -in "$temp_cert" -noout -subject 2>/dev/null | sed 's/subject=//')
    issuer=$(openssl x509 -in "$temp_cert" -noout -issuer 2>/dev/null | sed 's/issuer=//')
    start_date=$(openssl x509 -in "$temp_cert" -noout -startdate 2>/dev/null | sed 's/notBefore=//')
    end_date=$(openssl x509 -in "$temp_cert" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
    fingerprint=$(openssl x509 -in "$temp_cert" -noout -fingerprint -sha256 2>/dev/null | sed 's/SHA256 Fingerprint=//')
    if openssl x509 -in "$temp_cert" -noout -checkend 0 >/dev/null 2>&1; then
      status="Valid"
    else
      status="Expired"
    fi
    echo -e "${YELLOW}Subject:${NC} ${subject:-N/A}"
    echo -e "${YELLOW}Issuer:${NC} ${issuer:-N/A}"
    echo -e "${YELLOW}Valid From:${NC} ${start_date:-N/A}"
    echo -e "${YELLOW}Valid To:${NC} ${end_date:-N/A}"
    echo -e "${YELLOW}Fingerprint:${NC} sha256 Fingerprint=${fingerprint:-N/A}"
    echo -e "${YELLOW}Status:${NC} $status"
    rm -f "$temp_cert"
  else
    display_error "Failed to retrieve certificate from $target:$port (connection error or timeout)"
  fi
}

# Display directories
display_directories() {
  local file_list="$1"
  local title="$2"
  display_title "$title Directories"
  if [ -s "$file_list" ]; then
    # Extract unique directories and count files
    sort "$file_list" | while IFS= read -r file; do
      dirname "$file"
    done | uniq -c | while read -r count dir; do
      echo "$dir ($count files)"
    done | nl -w2 -s". "
  else
    echo "No $title found."
  fi
}

# Display SSL details
display_ssl_details() {
  display_title "SSL/TLS Details"
  if [ -s "$TEMP_SSL" ]; then
    sort "$TEMP_SSL" | while IFS= read -r file; do
      echo -e "${YELLOW}SSL Certificate:${NC} $(basename "$file")"
      echo -e "${YELLOW}Path:${NC} $file"
      subject="N/A"
      issuer="N/A"
      start_date="N/A"
      end_date="N/A"
      fingerprint="N/A"
      status="Unknown"
      if [[ "$file" == *.p12 ]]; then
        # Extract certificate from PKCS#12 for details
        if cert_data=$(openssl pkcs12 -in "$file" -nodes -nokeys -passin pass:"" 2>/dev/null); then
          subject=$(echo "$cert_data" | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//')
          issuer=$(echo "$cert_data" | openssl x509 -noout -issuer 2>/dev/null | sed 's/issuer=//')
          start_date=$(echo "$cert_data" | openssl x509 -noout -startdate 2>/dev/null | sed 's/notBefore=//')
          end_date=$(echo "$cert_data" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
          fingerprint=$(echo "$cert_data" | openssl x509 -noout -fingerprint -sha256 2>/dev/null | sed 's/SHA256 Fingerprint=//')
          if echo "$cert_data" | openssl x509 -noout -checkend 0 >/dev/null 2>&1; then
            status="Valid"
          else
            status="Expired"
          fi
        fi
      else
        subject=$(openssl x509 -in "$file" -noout -subject 2>/dev/null | sed 's/subject=//')
        issuer=$(openssl x509 -in "$file" -noout -issuer 2>/dev/null | sed 's/issuer=//')
        start_date=$(openssl x509 -in "$file" -noout -startdate 2>/dev/null | sed 's/notBefore=//')
        end_date=$(openssl x509 -in "$file" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
        fingerprint=$(openssl x509 -in "$file" -noout -fingerprint -sha256 2>/dev/null | sed 's/SHA256 Fingerprint=//')
        if openssl x509 -in "$file" -noout -checkend 0 >/dev/null 2>&1; then
          status="Valid"
        else
          status="Expired"
        fi
      fi
      echo -e "${YELLOW}Subject:${NC} ${subject:-N/A}"
      echo -e "${YELLOW}Issuer:${NC} ${issuer:-N/A}"
      echo -e "${YELLOW}Valid From:${NC} ${start_date:-N/A}"
      echo -e "${YELLOW}Valid To:${NC} ${end_date:-N/A}"
      echo -e "${YELLOW}Fingerprint:${NC} sha256 Fingerprint=${fingerprint:-N/A}"
      echo -e "${YELLOW}Status:${NC} $status"
      echo
    done
  else
    echo "No SSL/TLS certificates found."
  fi
}

# Display SSH details
display_ssh_details() {
  display_title "SSH Details"
  if [ -s "$TEMP_SSH" ]; then
    sort "$TEMP_SSH" | while IFS= read -r file; do
      echo -e "${YELLOW}SSH Key:${NC} $(basename "$file")"
      echo -e "${YELLOW}Path:${NC} $file"
      key_type="Unknown"
      bits="Unknown"
      fingerprint="Unknown"
      comment="N/A"
      permissions="N/A"
      if [[ "$file" == *.pub ]]; then
        key_type="Public"
        read -r _ bits comment _ < <(ssh-keygen -l -f "$file" 2>/dev/null)
        fingerprint=$(ssh-keygen -l -f "$file" 2>/dev/null | cut -d' ' -f2)
      else
        key_type="Private"
        if ssh-keygen -y -P "" -f "$file" >/dev/null 2>&1; then
          read -r _ bits comment _ < <(ssh-keygen -l -f "$file" 2>/dev/null)
          fingerprint=$(ssh-keygen -l -f "$file" 2>/dev/null | cut -d' ' -f2)
        fi
        permissions=$(stat -c "%a" "$file" 2>/dev/null)
      fi
      echo -e "${YELLOW}Type:${NC} $comment"
      echo -e "${YELLOW}Bits:${NC} ${bits:-N/A}"
      echo -e "${YELLOW}Fingerprint:${NC} ${fingerprint:-N/A}"
      echo -e "${YELLOW}Key Type:${NC} $key_type"
      echo -e "${YELLOW}Permissions:${NC} $permissions"
      echo
    done
  else
    echo "No SSH keys found."
  fi
}

# Display PGP details
display_pgp_details() {
  display_title "PGP Details"
  if [ -s "$TEMP_PGP" ]; then
    sort "$TEMP_PGP" | while IFS= read -r file; do
      echo -e "${YELLOW}PGP Key:${NC} $(basename "$file")"
      echo -e "${YELLOW}Path:${NC} $file"
      key_type="Unknown"
      uid="Unknown"
      key_id="N/A"
      if gpg --list-packets "$file" >/dev/null 2>&1; then
        uid_info=$(gpg --list-keys --with-colons "$file" 2>/dev/null | grep '^uid' | cut -d':' -f10)
        if [ -n "$uid_info" ]; then
          uid="$uid_info"
        fi
        key_id=$(gpg --list-keys --with-colons "$file" 2>/dev/null | grep '^pub' | cut -d':' -f5 | tail -n 1)
      fi
      echo -e "${YELLOW}Type:${NC} $key_type"
      echo -e "${YELLOW}UID:${NC} $uid"
      echo -e "${YELLOW}Key ID:${NC} $key_id"
      echo
    done
  else
    echo "No PGP keys found."
  fi
}

# Detect services listening on port 443 and their associated certificates
detect_services_443() {
  display_title "Detecting Services on Port 443"
  > "$TEMP_SERVICES"
  > "$TEMP_USED_CERTS"

  # Use ss or netstat to find services listening on port 443
  if command -v ss >/dev/null 2>&1; then
    ss -tuln | grep ":443" | while IFS= read -r line; do
      local pid=$(ss -tulp | grep ":443" | awk '{print $NF}' | grep -oP 'pid=\K[0-9]+')
      if [ -n "$pid" ]; then
        local binary=$(ps -p "$pid" -o comm= 2>/dev/null)
        local cmdline=$(cat /proc/"$pid"/cmdline 2>/dev/null | tr '\0' ' ')
        echo "PID: $pid, Binary: $binary, Cmdline: $cmdline" >> "$TEMP_SERVICES"
        find_service_certs "$binary" "$pid" "$cmdline"
      fi
    done
  elif command -v netstat >/dev/null 2>&1; then
    netstat -tuln | grep ":443" | while IFS= read -r line; do
      local pid=$(netstat -tulnp 2>/dev/null | grep ":443" | awk '{print $NF}' | cut -d'/' -f1)
      if [ -n "$pid" ]; then
        local binary=$(ps -p "$pid" -o comm= 2>/dev/null)
        local cmdline=$(cat /proc/"$pid"/cmdline 2>/dev/null | tr '\0' ' ')
        echo "PID: $pid, Binary: $binary, Cmdline: $cmdline" >> "$TEMP_SERVICES"
        find_service_certs "$binary" "$pid" "$cmdline"
      fi
    done
  else
    display_error "Neither ss nor netstat is available. Cannot detect services."
    return 1
  fi

  # Display results
  if [ -s "$TEMP_SERVICES" ]; then
    display_success "Services detected on port 443:"
    nl -w2 -s". " "$TEMP_SERVICES"
  else
    display_info "No services found listening on port 443."
  fi
}

# Find certificates used by a specific service
find_service_certs() {
  local binary="$1"
  local pid="$2"
  local cmdline="$3"
  local cert_file=""

  case "$binary" in
    nginx)
      local nginx_conf="/etc/nginx/nginx.conf"
      local nginx_sites="/etc/nginx/sites-enabled/*"
      if [ -f "$nginx_conf" ]; then
        grep -h "ssl_certificate[^_]" "$nginx_conf" $nginx_sites 2>/dev/null | grep -v "#" | while IFS= read -r line; do
          cert_file=$(echo "$line" | awk '{print $2}' | tr -d ';')
          if [ -f "$cert_file" ]; then
            echo "$cert_file" >> "$TEMP_USED_CERTS"
          fi
        done
      fi
      ;;
    httpd | apache2)
      local apache_conf="/etc/apache2/apache2.conf"
      local apache_sites="/etc/apache2/sites-enabled/*"
      if [ -f "$apache_conf" ]; then
        grep -h "SSLCertificateFile" "$apache_conf" $apache_sites 2>/dev/null | grep -v "#" | while IFS= read -r line; do
          cert_file=$(echo "$line" | awk '{print $2}')
          if [ -f "$cert_file" ]; then
            echo "$cert_file" >> "$TEMP_USED_CERTS"
          fi
        done
      fi
      ;;
    java)
      # Check for Tomcat or other Java-based services
      find / -type f -name "server.xml" 2>/dev/null | while IFS= read -r file; do
        grep -h "certificateKeystoreFile" "$file" 2>/dev/null | grep -v "<!--" | while IFS= read -r line; do
          cert_file=$(echo "$line" | grep -oP 'certificateKeystoreFile="\K[^"]+')
          if [ -f "$cert_file" ]; then
            echo "$cert_file" >> "$TEMP_USED_CERTS"
          fi
        done
      done
      ;;
    *)
      display_info "Unknown binary $binary. Checking cmdline for certificate paths..."
      echo "$cmdline" | grep -oP '\S+\.(crt|pem|p12)' | while IFS= read -r file; do
        if [ -f "$file" ]; then
          echo "$file" >> "$TEMP_USED_CERTS"
        fi
      done
      ;;
  esac
}

# Scan for all certificates and keys, including unused ones
scan_all_certs() {
  display_title "Scanning All Certificates and Keys"
  > "$TEMP_ALL_CERTS"

  local exclude_paths="-not -path '/proc/*' -not -path '/sys/*' -not -path '/dev/*' -not -path '/run/*'"
  local search_dirs="/etc /opt"

  # Search for certificates and keys with specific patterns
  find $search_dirs -type f \( -name "*.crt" -o -name "*.pem" -o -name "*.cer" -o -name "*.p12" -o -name "*.key" \) $exclude_paths 2>/dev/null | while IFS= read -r file; do
    # Filter files containing 'amj-groupe' or common certificate patterns
    if strings "$file" 2>/dev/null | grep -qi "amj-groupe\|CERTIFICATE\|PRIVATE KEY"; then
      if [[ "$file" == *.key ]]; then
        if openssl rsa -in "$file" -noout 2>/dev/null || openssl ec -in "$file" -noout 2>/dev/null; then
          echo "$file (Private Key)" >> "$TEMP_ALL_CERTS"
        else
          echo "Key: $file (invalid key format)" >> "$TEMP_ERRORS"
        fi
      elif [[ "$file" == *.p12 ]]; then
        if openssl pkcs12 -in "$file" -nodes -nokeys -passin pass:"" | openssl x509 -noout >/dev/null 2>&1; then
          echo "$file (PKCS#12)" >> "$TEMP_ALL_CERTS"
        else
          echo "PKCS#12: $file (invalid format)" >> "$TEMP_ERRORS"
        fi
      else
        if openssl x509 -in "$file" -noout >/dev/null 2>&1; then
          echo "$file (Certificate)" >> "$TEMP_ALL_CERTS"
        else
          echo "Certificate: $file (invalid format)" >> "$TEMP_ERRORS"
        fi
      fi
    fi
  done

  # Display results
  local all_count=$(wc -l < "$TEMP_ALL_CERTS")
  display_success "Found $all_count certificates and keys."
}

# Compare used vs unused certificates
compare_certs() {
  display_title "Comparing Used vs Unused Certificates"
  local temp_unused="/tmp/unused_certs_$$.txt"
  > "$temp_unused"

  # Find certificates in TEMP_ALL_CERTS but not in TEMP_USED_CERTS
  sort "$TEMP_ALL_CERTS" | uniq | while IFS= read -r line; do
    local file=$(echo "$line" | cut -d' ' -f1)
    if ! grep -Fx "$file" "$TEMP_USED_CERTS" >/dev/null 2>&1; then
      echo "$line" >> "$temp_unused"
    fi
  done

  # Display unused certificates
  if [ -s "$temp_unused" ]; then
    display_info "Unused certificates and keys:"
    nl -w2 -s". " "$temp_unused"
  else
    display_info "No unused certificates or keys found."
  fi

  rm -f "$temp_unused"
}

# Perform a complete machine audit
complete_machine_audit() {
  display_title "Complete Machine Audit"
  > "$TEMP_AUDIT"

  # Step 1: Detect services and their certificates
  detect_services_443

  # Step 2: Scan all certificates and keys
  scan_all_certs

  # Step 3: Compare used vs unused
  compare_certs

  # Step 4: Generate CSV-compatible summary
  display_info "Generating audit summary for Excel..."
  echo "Path,Type,Key Path,Expiration Date,Common Name,Issuer,Status" > "$TEMP_AUDIT"

  # Process used certificates
  if [ -s "$TEMP_USED_CERTS" ]; then
    sort -u "$TEMP_USED_CERTS" | while IFS= read -r file; do
      local type="Certificate"
      local key_path="N/A"
      local expiration="N/A"
      local cn="N/A"
      local issuer="N/A"
      local status="Unknown"
      if [[ "$file" == *.p12 ]]; then
        type="PKCS#12"
        if cert_data=$(openssl pkcs12 -in "$file" -nodes -nokeys -passin pass:"" 2>/dev/null); then
          cn=$(echo "$cert_data" | openssl x509 -noout -subject 2>/dev/null | grep -oP 'CN=\K[^,]+')
          issuer=$(echo "$cert_data" | openssl x509 -noout -issuer 2>/dev/null | grep -oP 'CN=\K[^,]+')
          expiration=$(echo "$cert_data" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
          status=$(echo "$cert_data" | openssl x509 -noout -checkend 0 >/dev/null 2>&1 && echo "Valid" || echo "Expired")
        fi
      else
        cn=$(openssl x509 -in "$file" -noout -subject 2>/dev/null | grep -oP 'CN=\K[^,]+')
        issuer=$(openssl x509 -in "$file" -noout -issuer 2>/dev/null | grep -oP 'CN=\K[^,]+')
        expiration=$(openssl x509 -in "$file" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
        status=$(openssl x509 -in "$file" -noout -checkend 0 >/dev/null 2>&1 && echo "Valid" || echo "Expired")
        # Try to find associated key
        local base_dir=$(dirname "$file")
        local base_name=$(basename "$file" .crt | basename - .pem | basename - .cer)
        key_path=$(find "$base_dir" -maxdepth 1 -name "$base_name.key" -o -name "*.key" | head -n 1)
        [ -z "$key_path" ] && key_path="N/A"
      fi
      echo "$file,$type,$key_path,$expiration,$cn,$issuer,$status" >> "$TEMP_AUDIT"
    done
  fi

  # Process all certificates (including unused)
  if [ -s "$TEMP_ALL_CERTS" ]; then
    sort -u "$TEMP_ALL_CERTS" | while IFS= read -r line; do
      local file=$(echo "$line" | cut -d' ' -f1)
      local type=$(echo "$line" | cut -d' ' -f2- | tr -d '()')
      local key_path="N/A"
      local expiration="N/A"
      local cn="N/A"
      local issuer="N/A"
      local status="Unknown"
      if [[ "$type" == "Private Key" ]]; then
        key_path="$file"
        type="Private Key"
      elif [[ "$type" == "PKCS#12" ]]; then
        if cert_data=$(openssl pkcs12 -in "$file" -nodes -nokeys -passin pass:"" 2>/dev/null); then
          cn=$(echo "$cert_data" | openssl x509 -noout -subject 2>/dev/null | grep -oP 'CN=\K[^,]+')
          issuer=$(echo "$cert_data" | openssl x509 -noout -issuer 2>/dev/null | grep -oP 'CN=\K[^,]+')
          expiration=$(echo "$cert_data" | openssl x509 -noout -enddate 2>/dev/null | sed 's/notAfter=//')
          status=$(echo "$cert_data" | openssl x509 -noout -checkend 0 >/dev/null 2>&1 && echo "Valid" || echo "Expired")
        fi
      else
        cn=$(openssl x509 -in "$file" -noout -subject 2>/dev/null | grep -oP 'CN=\K[^,]+')
        issuer=$(openssl x509 -in "$file" -noout -issuer 2>/dev/null | grep -oP 'CN=\K[^,]+')
        expiration=$(openssl x509 -in "$file" -noout -enddate 2>/dev/null | sed 's/notAfter=//')
        status=$(openssl x509 -in "$file" -noout -checkend 0 >/dev/null 2>&1 && echo "Valid" || echo "Expired")
        local base_dir=$(dirname "$file")
        local base_name=$(basename "$file" .crt | basename - .pem | basename - .cer)
        key_path=$(find "$base_dir" -maxdepth 1 -name "$base_name.key" -o -name "*.key" | head -n 1)
        [ -z "$key_path" ] && key_path="N/A"
      fi
      # Only add if not already in used certs to avoid duplicates
      if ! grep -Fx "$file" "$TEMP_USED_CERTS" >/dev/null 2>&1; then
        echo "$file,$type,$key_path,$expiration,$cn,$issuer,$status" >> "$TEMP_AUDIT"
      fi
    done
  fi

  # Display summary
  display_success "Audit complete. Summary saved to $TEMP_AUDIT"
  display_info "CSV format for Excel:"
  cat "$TEMP_AUDIT" | column -t -s,
}

# Display errors
display_errors() {
  display_title "Files with Issues"
  if [ -s "$TEMP_ERRORS" ]; then
    nl -w2 -s". " "$TEMP_ERRORS"
  else
    echo "No issues found."
  fi
}

# Main menu
main_menu() {
  while true; do
    display_title "Certificate Explorer"
    echo "Select an option:"
    echo "1. SSL/TLS"
    echo "2. SSH"
    echo "3. PGP"
    echo "4. Errors"
    echo "5. Filter SSL"
    echo "6. All"
    echo "7. Exit"
    echo "8. Services Web Locaux"
    echo "9. Certificats Distants (DNS/IP)"
    echo "11. Audit complet machine (Services + Certificats présents + Utilisés)"
    read -p "Choice [1-9,11]: " choice
    case $choice in
      1)
        display_directories "$TEMP_SSL" "SSL/TLS"
        display_ssl_details
        ;;
      2)
        display_directories "$TEMP_SSH" "SSH"
        display_ssh_details
        ;;
      3)
        display_directories "$TEMP_PGP" "PGP"
        display_pgp_details
        ;;
      4)
        display_errors
        ;;
      5)
        display_info "Filtering SSL certificates (not implemented yet)..."
        ;;
      6)
        display_directories "$TEMP_SSL" "SSL/TLS"
        display_ssl_details
        display_directories "$TEMP_SSH" "SSH"
        display_ssh_details
        display_directories "$TEMP_PGP" "PGP"
        display_pgp_details
        display_errors
        ;;
      7)
        display_success "Exiting..."
        exit 0
        ;;
      8)
        scan_web_services_certs
        ;;
      9)
        scan_remote_cert
        ;;
      11)
        complete_machine_audit
        ;;
      *)
        display_error "Invalid choice. Please select 1-9 or 11."
        ;;
    esac
    read -p "Press Enter to continue..."
  done
}

# Main execution
ask_scan_scope
scan_system
main_menu
