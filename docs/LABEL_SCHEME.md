# Internal Label Scheme — CYBER_MultiTool

Every CVE ingested into the database receives a structured internal label. This label enables security operators and automated tooling to instantly determine the platform, architectural layer, vendor/product, and severity of a vulnerability.

---

## 1. Label Format
The label is constructed from seven hyphen-separated segments:
```
[OS_FAMILY]-[OS_DISTRO]-[LAYER]-[PRODUCT]-[SEVERITY]-[CVE_YEAR]-[CVE_SEQ]
```

### Example Labels
- `LIN-RHEL-DB-MYSQL-H-2024-1234`
  - Linux, Red Hat Enterprise Linux, Database Layer, MySQL, High Severity, Year 2024, Sequence 1234.
- `WIN-ANY-OS-RDPSTACK-C-2020-609`
  - Windows, Any Distro, Operating System Layer, RDP Stack, Critical Severity, Year 2020, Sequence 609.
- `ANY-ANY-WEB-APACHE-H-2021-41773`
  - Cross-platform, Any Distro, Web Server Layer, Apache, High Severity, Year 2021, Sequence 41773.
- `CONT-ANY-OS-RUNC-C-2024-21626`
  - Container-specific, Any Distro, Operating System/Container Runtime, runc, Critical Severity, Year 2024, Sequence 21626.
- `LIN-UBU-KERN-KERNEL-C-2024-1086`
  - Linux, Ubuntu, Kernel Layer, Linux Kernel, Critical Severity, Year 2024, Sequence 1086.

---

## 2. Segment Mappings

### Segment 1: OS_FAMILY
Identifies the primary operating system category:
- `LIN`  = Linux-based environments.
- `WIN`  = Microsoft Windows variants.
- `MAC`  = Apple macOS / iOS.
- `CONT` = Containerization/orchestration layer (e.g., Docker, Kubernetes, containerd, runc).
- `NET`  = Network appliance hardware/stack (e.g., Cisco IOS, Fortinet FortiOS, PAN-OS).
- `ANY`  = Cross-platform dependencies or unknown operating systems.

### Segment 2: OS_DISTRO
Specifies the Linux distribution (applicable when `OS_FAMILY` is `LIN`):
- `RHEL` = Red Hat Enterprise Linux, CentOS, Rocky Linux, AlmaLinux.
- `UBU`  = Ubuntu (Canonical).
- `DEB`  = Debian GNU/Linux.
- `ARCH` = Arch Linux, CachyOS, Manjaro.
- `SUSE` = openSUSE, SUSE Linux Enterprise.
- `FED`  = Fedora.
- `ANY`  = Not distribution-specific or applicable to other OS families.

### Segment 3: LAYER
Categorizes the architectural tier of the affected component:
- `KERN` = Operating system kernels (e.g., Linux Kernel).
- `OS`   = Base operating system userland components, libraries, and utilities.
- `DB`   = Databases (e.g., MySQL, PostgreSQL, MongoDB, Redis, SQLite).
- `WEB`  = Web servers, proxies, and application frameworks (e.g., Nginx, Apache, Tomcat, IIS, Django).
- `NET`  = Network stack, VPNs, routing, and firewalls.
- `APP`  = User-space applications (e.g., browsers, office packages, kibana, desktop clients).
- `MW`   = Message brokers and middleware (e.g., RabbitMQ, Kafka, ActiveMQ, HAProxy).
- `CONT` = Container execution runtime engines (e.g., Docker, Kubernetes, runc).
- `FW`   = Device firmware (hardware bios, BIOS, hardware controller drivers).
- `LIB`  = General software development libraries and package dependencies (e.g., OpenSSL, Curl, Log4j).
- `PKG`  = Language runtimes or package manager tools (e.g., Python, Node.js, Ruby, pip, npm).

### Segment 4: PRODUCT
A cleaned representation of the software component, derived from the CPE product field:
- Uppercased.
- Sanitized to retain alphanumeric characters only.
- Truncated to a maximum of 10 characters.
- Examples: `MYSQL`, `NGINX`, `OPENSSH`, `OPENSSL`, `LOG4J`, `RUNC`, `KERNEL`.

### Segment 5: SEVERITY
Derived from the highest available CVSS base score:
- `C` = Critical (CVSS Score `9.0` – `10.0`)
- `H` = High (CVSS Score `7.0` – `8.9`)
- `M` = Medium (CVSS Score `4.0` – `6.9`)
- `L` = Low (CVSS Score `0.1` – `3.9`)
- `I` = Info (CVSS Score `0.0` or score is missing)

### Segment 6: CVE_YEAR
The 4-digit calendar year retrieved from the CVE ID (e.g., `2024`).

### Segment 7: CVE_SEQ
The unique sequence number retrieved from the CVE ID, represented without leading zeros (e.g. `CVE-2024-0609` -> `609`).
