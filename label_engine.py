#!/usr/bin/env python3
"""
label_engine.py
CYBER_MultiTool CVE internal labeling system.
Parses CPE data, CVSS metrics, and CVE metadata to generate unique internal labels.
"""

# VENDOR_PRODUCT_MAP maps (vendor, product) -> (OS_FAMILY, OS_DISTRO, LAYER)
VENDOR_PRODUCT_MAP = {
    # Databases
    ("oracle", "mysql"): ("ANY", "ANY", "DB"),
    ("mysql", "mysql"): ("ANY", "ANY", "DB"),
    ("postgresql", "postgresql"): ("ANY", "ANY", "DB"),
    ("postgresql", "postgres"): ("ANY", "ANY", "DB"),
    ("postgres", "postgres"): ("ANY", "ANY", "DB"),
    ("mongodb", "mongodb"): ("ANY", "ANY", "DB"),
    ("redis", "redis"): ("ANY", "ANY", "DB"),
    ("sqlite", "sqlite"): ("ANY", "ANY", "DB"),
    ("microsoft", "sql_server"): ("WIN", "ANY", "DB"),
    ("elasticsearch", "elasticsearch"): ("ANY", "ANY", "DB"),
    ("elastic", "elasticsearch"): ("ANY", "ANY", "DB"),
    ("mariadb", "mariadb"): ("ANY", "ANY", "DB"),
    ("oracle", "oracle_database"): ("ANY", "ANY", "DB"),
    ("oracle", "database_server"): ("ANY", "ANY", "DB"),
    ("cassandra", "cassandra"): ("ANY", "ANY", "DB"),
    ("neo4j", "neo4j"): ("ANY", "ANY", "DB"),
    ("influxdata", "influxdb"): ("ANY", "ANY", "DB"),
    ("couchbase", "couchbase"): ("ANY", "ANY", "DB"),

    # Web servers & frameworks
    ("apache", "http_server"): ("ANY", "ANY", "WEB"),
    ("apache", "apache"): ("ANY", "ANY", "WEB"),
    ("nginx", "nginx"): ("ANY", "ANY", "WEB"),
    ("microsoft", "iis"): ("WIN", "ANY", "WEB"),
    ("lighttpd", "lighttpd"): ("ANY", "ANY", "WEB"),
    ("apache", "tomcat"): ("ANY", "ANY", "WEB"),
    ("eclipse", "jetty"): ("ANY", "ANY", "WEB"),
    ("palletsprojects", "flask"): ("ANY", "ANY", "WEB"),
    ("rubyonrails", "rails"): ("ANY", "ANY", "WEB"),
    ("django", "django"): ("ANY", "ANY", "WEB"),
    ("fastapi", "fastapi"): ("ANY", "ANY", "WEB"),
    ("expressjs", "express"): ("ANY", "ANY", "WEB"),
    ("springsource", "spring_framework"): ("ANY", "ANY", "LIB"),
    ("pivotal_software", "spring_framework"): ("ANY", "ANY", "LIB"),
    ("vmware", "spring_framework"): ("ANY", "ANY", "LIB"),
    ("apache", "struts"): ("ANY", "ANY", "LIB"),
    ("caddyserver", "caddy"): ("ANY", "ANY", "WEB"),
    ("caddy", "caddy"): ("ANY", "ANY", "WEB"),

    # OS / Kernel
    ("linux", "linux_kernel"): ("LIN", "ANY", "KERN"),
    ("linux_kernel", "linux_kernel"): ("LIN", "ANY", "KERN"),
    ("microsoft", "windows_nt"): ("WIN", "ANY", "OS"),
    ("microsoft", "windows"): ("WIN", "ANY", "OS"),
    ("apple", "macos"): ("MAC", "ANY", "OS"),
    ("apple", "mac_os_x"): ("MAC", "ANY", "OS"),
    ("apple", "iphone_os"): ("MAC", "ANY", "OS"),
    ("google", "android"): ("LIN", "ANY", "OS"),

    # Linux distros
    ("redhat", "enterprise_linux"): ("LIN", "RHEL", "OS"),
    ("redhat", "rhel"): ("LIN", "RHEL", "OS"),
    ("centos", "centos"): ("LIN", "RHEL", "OS"),
    ("rockylinux", "rocky_linux"): ("LIN", "RHEL", "OS"),
    ("almalinux", "almalinux"): ("LIN", "RHEL", "OS"),
    ("canonical", "ubuntu"): ("LIN", "UBU", "OS"),
    ("ubuntu", "ubuntu_linux"): ("LIN", "UBU", "OS"),
    ("debian", "debian"): ("LIN", "DEB", "OS"),
    ("debian", "debian_gnu/linux"): ("LIN", "DEB", "OS"),
    ("debian", "debian_linux"): ("LIN", "DEB", "OS"),
    ("fedora", "fedora"): ("LIN", "FED", "OS"),
    ("fedora_project", "fedora"): ("LIN", "FED", "OS"),
    ("opensuse", "opensuse"): ("LIN", "SUSE", "OS"),
    ("suse", "suse_linux"): ("LIN", "SUSE", "OS"),
    ("suse", "suse"): ("LIN", "SUSE", "OS"),
    ("archlinux", "arch_linux"): ("LIN", "ARCH", "OS"),
    ("archlinux", "arch"): ("LIN", "ARCH", "OS"),
    ("cachyos", "cachyos"): ("LIN", "ARCH", "OS"),
    ("manjaro", "manjaro"): ("LIN", "ARCH", "OS"),

    # Network
    ("cisco", "ios"): ("NET", "ANY", "OS"),
    ("cisco", "ios_xe"): ("NET", "ANY", "OS"),
    ("cisco", "nx-os"): ("NET", "ANY", "OS"),
    ("cisco", "asa"): ("NET", "ANY", "NET"),
    ("cisco", "adaptive_security_appliance"): ("NET", "ANY", "NET"),
    ("juniper", "junos"): ("NET", "ANY", "OS"),
    ("juniper", "screenos"): ("NET", "ANY", "OS"),
    ("juniper", "srx"): ("NET", "ANY", "NET"),
    ("fortinet", "fortios"): ("NET", "ANY", "OS"),
    ("fortinet", "fortigate"): ("NET", "ANY", "NET"),
    ("paloalto", "pan-os"): ("NET", "ANY", "OS"),
    ("palo_alto", "pan-os"): ("NET", "ANY", "OS"),
    ("f5", "big-ip"): ("NET", "ANY", "OS"),
    ("f5", "bigip"): ("NET", "ANY", "OS"),
    ("citrix", "netscaler"): ("NET", "ANY", "OS"),
    ("sonicwall", "sonicos"): ("NET", "ANY", "OS"),
    ("checkpoint", "gaia"): ("NET", "ANY", "OS"),

    # Containers
    ("docker", "docker"): ("CONT", "ANY", "CONT"),
    ("kubernetes", "kubernetes"): ("CONT", "ANY", "CONT"),
    ("containerd", "containerd"): ("CONT", "ANY", "CONT"),
    ("runc_project", "runc"): ("CONT", "ANY", "CONT"),
    ("opencontainers", "runc"): ("CONT", "ANY", "CONT"),
    ("podman_project", "podman"): ("CONT", "ANY", "CONT"),
    ("cri-o", "cri-o"): ("CONT", "ANY", "CONT"),
    ("hashicorp", "nomad"): ("CONT", "ANY", "CONT"),
    ("rancher", "k3s"): ("CONT", "ANY", "CONT"),
    ("coreos", "etcd"): ("CONT", "ANY", "CONT"),

    # Middleware
    ("rabbitmq", "rabbitmq"): ("ANY", "ANY", "MW"),
    ("pivotal", "rabbitmq"): ("ANY", "ANY", "MW"),
    ("apache", "kafka"): ("ANY", "ANY", "MW"),
    ("apache", "activemq"): ("ANY", "ANY", "MW"),
    ("haproxy", "haproxy"): ("ANY", "ANY", "MW"),
    ("envoyproxy", "envoy"): ("ANY", "ANY", "MW"),
    ("envoy", "envoy"): ("ANY", "ANY", "MW"),
    ("istio", "istio"): ("ANY", "ANY", "MW"),
    ("elastic", "logstash"): ("ANY", "ANY", "MW"),
    ("hashicorp", "consul"): ("ANY", "ANY", "MW"),
    ("nginx_ingress", "nginx_ingress"): ("CONT", "ANY", "MW"),

    # Libraries
    ("openssl", "openssl"): ("ANY", "ANY", "LIB"),
    ("openssl_project", "openssl"): ("ANY", "ANY", "LIB"),
    ("openssl", "libssl"): ("ANY", "ANY", "LIB"),
    ("curl", "curl"): ("ANY", "ANY", "LIB"),
    ("haxx", "curl"): ("ANY", "ANY", "LIB"),
    ("libcurl", "curl"): ("ANY", "ANY", "LIB"),
    ("zlib", "zlib"): ("ANY", "ANY", "LIB"),
    ("madler", "zlib"): ("ANY", "ANY", "LIB"),
    ("apache", "log4j"): ("ANY", "ANY", "LIB"),
    ("apache", "log4net"): ("ANY", "ANY", "LIB"),
    ("libpng", "libpng"): ("ANY", "ANY", "LIB"),
    ("ijg", "libjpeg"): ("ANY", "ANY", "LIB"),
    ("gnu", "glibc"): ("LIN", "ANY", "LIB"),
    ("glibc", "glibc"): ("LIN", "ANY", "LIB"),
    ("google", "protobuf"): ("ANY", "ANY", "LIB"),

    # Language runtimes / package managers
    ("python", "python"): ("ANY", "ANY", "PKG"),
    ("ruby-lang", "ruby"): ("ANY", "ANY", "PKG"),
    ("nodejs", "node.js"): ("ANY", "ANY", "PKG"),
    ("nodejs", "nodejs"): ("ANY", "ANY", "PKG"),
    ("golang", "go"): ("ANY", "ANY", "PKG"),
    ("oracle", "jre"): ("ANY", "ANY", "PKG"),
    ("oracle", "jdk"): ("ANY", "ANY", "PKG"),
    ("python", "pip"): ("ANY", "ANY", "PKG"),
    ("npmjs", "npm"): ("ANY", "ANY", "PKG"),
    ("rubygems", "gem"): ("ANY", "ANY", "PKG"),
    ("rust-lang", "rust"): ("ANY", "ANY", "PKG"),

    # Browsers / Client applications
    ("google", "chrome"): ("ANY", "ANY", "APP"),
    ("mozilla", "firefox"): ("ANY", "ANY", "APP"),
    ("apple", "safari"): ("MAC", "ANY", "APP"),
    ("microsoft", "edge"): ("WIN", "ANY", "APP"),
    ("microsoft", "internet_explorer"): ("WIN", "ANY", "APP"),
    ("adobe", "acrobat"): ("ANY", "ANY", "APP"),
    ("adobe", "reader"): ("ANY", "ANY", "APP"),
    ("microsoft", "office"): ("WIN", "ANY", "APP"),
    ("zoom", "zoom"): ("ANY", "ANY", "APP"),
    ("slack", "slack"): ("ANY", "ANY", "APP"),
    ("elastic", "kibana"): ("ANY", "ANY", "APP"),
    ("grafana", "grafana"): ("ANY", "ANY", "APP"),
    ("prometheus", "prometheus"): ("ANY", "ANY", "APP"),
    ("jenkins", "jenkins"): ("ANY", "ANY", "APP"),
    ("gitlab", "gitlab"): ("ANY", "ANY", "APP"),
    ("github", "github"): ("ANY", "ANY", "APP"),
    ("atlassian", "jira"): ("ANY", "ANY", "APP"),
    ("atlassian", "confluence"): ("ANY", "ANY", "APP"),
}


def parse_cpe(cpe_uri: str) -> dict:
    """
    Parses a CPE 2.3 URI into its constituent parts.
    cpe:2.3:part:vendor:product:version:...
    """
    if not cpe_uri or not cpe_uri.startswith("cpe:"):
        return {}
    parts = cpe_uri.split(":")
    if len(parts) < 5:
        return {}
    return {
        "part": parts[2],
        "vendor": parts[3],
        "product": parts[4]
    }


def generate_label(cve_id: str, products: list[dict], metrics: list[dict]) -> str:
    """
    Generates a custom internal label for a CVE based on affected products and metrics.
    Label format: [OS_FAMILY]-[OS_DISTRO]-[LAYER]-[PRODUCT]-[SEVERITY]-[CVE_YEAR]-[CVE_SEQ]
    """
    # 1. Parse Year and Sequence from CVE ID (e.g., CVE-2024-1234 -> 2024, 1234)
    cve_year = "ANY"
    cve_seq = "ANY"
    parts = cve_id.split("-")
    if len(parts) >= 3:
        cve_year = parts[1]
        try:
            cve_seq = str(int(parts[2]))  # Strip leading zeros
        except ValueError:
            cve_seq = parts[2]

    # 2. Map Severity based on highest available CVSS base_score
    max_score = -1.0
    for m in metrics:
        score = m.get("base_score")
        if score is not None:
            try:
                max_score = max(max_score, float(score))
            except (ValueError, TypeError):
                pass

    if max_score >= 9.0:
        severity = "C"
    elif max_score >= 7.0:
        severity = "H"
    elif max_score >= 4.0:
        severity = "M"
    elif max_score >= 0.1:
        severity = "L"
    elif max_score == 0.0:
        severity = "I"
    else:
        severity = "I"

    # Default segments
    os_family = "ANY"
    os_distro = "ANY"
    layer = "LIB"
    product_name = "UNKNOWN"

    # 3. Analyze affected products
    chosen_product = None
    if products:
        # Prefer entries with cpe_uri, and prefer NVD sources
        for p in products:
            if p.get("cpe_uri"):
                chosen_product = p
                break
        if not chosen_product:
            chosen_product = products[0]

    if chosen_product:
        vendor = chosen_product.get("vendor", "")
        product = chosen_product.get("product", "")
        cpe_uri = chosen_product.get("cpe_uri", "")

        if cpe_uri:
            cpe_parts = parse_cpe(cpe_uri)
            if cpe_parts:
                vendor = cpe_parts.get("vendor", vendor)
                product = cpe_parts.get("product", product)
                part = cpe_parts.get("part", "")
                if part == "o":
                    layer = "OS"
                elif part == "h":
                    layer = "FW"

        vendor_lower = vendor.lower() if vendor else ""
        product_lower = product.lower() if product else ""

        # Map via vendor product lookup dictionary
        mapped = False
        if (vendor_lower, product_lower) in VENDOR_PRODUCT_MAP:
            os_family, os_distro, layer = VENDOR_PRODUCT_MAP[(vendor_lower, product_lower)]
            mapped = True

        # Heuristics if not mapped
        if not mapped:
            # Layer heuristics
            if "kernel" in product_lower or "linux_kernel" in product_lower:
                layer = "KERN"
                os_family = "LIN"
            elif any(db in product_lower for db in ["mysql", "postgres", "mongodb", "redis", "sqlite", "mariadb", "oracle"]):
                layer = "DB"
            elif any(web in product_lower for web in ["nginx", "apache", "httpd", "tomcat", "iis", "flask", "rails", "django"]):
                layer = "WEB"
            elif any(net in product_lower for net in ["vpn", "firewall", "router", "switch", "paloalto", "cisco", "juniper", "fortios"]):
                layer = "NET"
            elif any(cont in product_lower for cont in ["docker", "kubernetes", "k8s", "containerd", "runc"]):
                layer = "CONT"
                os_family = "CONT"
            elif any(mw in product_lower for mw in ["rabbitmq", "kafka", "activemq", "haproxy", "envoy"]):
                layer = "MW"
            elif any(pkg in product_lower for pkg in ["pip", "npm", "gem", "rustc", "python", "node"]):
                layer = "PKG"
            elif any(app in product_lower for app in ["chrome", "firefox", "safari", "acrobat", "slack", "office"]):
                layer = "APP"

            # OS Family heuristics
            if "linux" in product_lower or "linux" in vendor_lower:
                os_family = "LIN"
            elif "windows" in product_lower or "microsoft" in vendor_lower:
                os_family = "WIN"
            elif "apple" in vendor_lower or "macos" in product_lower or "mac_os" in product_lower:
                os_family = "MAC"
            elif any(c in product_lower for c in ["runc", "containerd", "docker", "kubernetes"]):
                os_family = "CONT"
            elif any(n in vendor_lower for n in ["cisco", "juniper", "fortinet", "palo_alto"]):
                os_family = "NET"

            # OS Distro heuristics (if LIN)
            if os_family == "LIN":
                if any(x in vendor_lower or x in product_lower for x in ["redhat", "rhel", "centos", "rocky", "almalinux"]):
                    os_distro = "RHEL"
                elif any(x in vendor_lower or x in product_lower for x in ["ubuntu", "canonical"]):
                    os_distro = "UBU"
                elif "debian" in vendor_lower or "debian" in product_lower:
                    os_distro = "DEB"
                elif any(x in vendor_lower or x in product_lower for x in ["arch", "cachyos", "manjaro"]):
                    os_distro = "ARCH"
                elif any(x in vendor_lower or x in product_lower for x in ["suse", "opensuse"]):
                    os_distro = "SUSE"
                elif "fedora" in vendor_lower or "fedora" in product_lower:
                    os_distro = "FED"

        if product:
            # Uppercased, alphanumeric only, truncated to 10 chars
            product_name = "".join(c for c in product.upper() if c.isalnum())
            product_name = product_name[:10]
            if not product_name:
                product_name = "UNKNOWN"
        else:
            product_name = "UNKNOWN"

    return f"{os_family}-{os_distro}-{layer}-{product_name}-{severity}-{cve_year}-{cve_seq}"
