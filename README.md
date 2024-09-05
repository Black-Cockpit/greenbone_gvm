# Greenbone GVM Ansible Collection

## Overview

This Ansible collection provides modules for managing Greenbone Vulnerability Manager (GVM) configurations, including credentials, schedules, targets, tasks, and audits. The collection is designed to interface with GVM using its API over Unix socket connections.

**Collection Name:** `greenbone_gvm`  
**Galaxy Namespace:** `hasnimehdi91`

## Requirements

- Ansible 2.10 or later
- GVM (Greenbone Vulnerability Manager) installed and accessible
- Proper permissions for managing GVM through the API
- The python libraries below should be installed on the target machine (The machine where Greenbone GVM is installed)

```bash
pip install python-gvm==24.8.0 --user
pip install xmltodict==0.13.0 --user
pip install netaddr==0.8.0 --user
pip install icalendar==5.0.7 --user
pip install validators==0.20.0 --user
```

## Installation

You can install the collection from Ansible Galaxy with the following command:

```bash
ansible-galaxy collection install hasnimehdi91.greenbone_gvm
```

## Modules

### gvm_credentials

Manage GVM credentials.

#### Parameters

- `socket_path` (string): Path to the GVM Unix socket. Example: `/run/gvmd/gvmd.sock`
- `gvm_username` (string): Username for GVM API authentication.
- `gvm_password` (string): Password for GVM API authentication.
- `name` (string): Name of the credential.
- `credential_type` (string): Type of the credential. Valid values include `USERNAME_PASSWORD`, `SNMP`, and `PGP_ENCRYPTION_KEY`.
- `login` (string, optional): Login name for the credential, required for some types (e.g., USERNAME_PASSWORD).
- `password` (string, optional): Password for the credential, required for some types (e.g., USERNAME_PASSWORD).
- `auth_algorithm` (string, optional): SNMP authentication algorithm, required for SNMP type. Valid values include `MD5`, `SHA1`.
- `privacy_algorithm` (string, optional): SNMP privacy algorithm, required for SNMP type. Valid values include `DES`, `AES`.
- `public_key_base64` (string, optional): Base64-encoded public key, required for PGP_ENCRYPTION_KEY type.
- `comment` (string, optional): Description of the credential.
- `state` (string): State of the credential. Valid values are `present` and `absent`.

#### Examples

- Create a USERNAME_PASSWORD credential:

    ```yaml
    - name: Create USERNAME_PASSWORD credential
      gvm_credentials:
        socket_path: "/run/gvmd/gvmd.sock"
        gvm_username: "admin"
        gvm_password: "admin"
        name: "My Credential"
        credential_type: "USERNAME_PASSWORD"
        login: "user123"
        password: "pass123"
        comment: "This is a test credential"
        state: present
    ```

- Create an SNMP credential:

    ```yaml
    - name: Create SNMP credential
      gvm_credentials:
        socket_path: "/run/gvmd/gvmd.sock"
        gvm_username: "admin"
        gvm_password: "admin"
        name: "SNMP Credential"
        credential_type: "SNMP"
        login: "snmpuser"
        password: "snmppass"
        auth_algorithm: "SHA1"
        privacy_algorithm: "AES"
        comment: "SNMP credential for monitoring"
        state: present
    ```

- Create a PGP encryption key credential:

    ```yaml
    - name: Create PGP encryption key credential
      gvm_credentials:
        socket_path: "/run/gvmd/gvmd.sock"
        gvm_username: "admin"
        gvm_password: "admin"
        name: "PGP Credential"
        credential_type: "PGP_ENCRYPTION_KEY"
        public_key_base64: "{{ lookup('file', '/path/to/public/key.asc') }}"
        comment: "PGP public key credential"
        state: present
    ```

- Delete a credential:

    ```yaml
    - name: Delete credential
      gvm_credentials:
        socket_path: "/run/gvmd/gvmd.sock"
        gvm_username: "admin"
        gvm_password: "admin"
        name: "Old Credential"
        state: absent
    ```

### gvm_schedule

Manage GVM schedules.

#### Parameters

- `socket_path` (string): Path to the GVM Unix socket. Example: `/run/gvmd/gvmd.sock`
- `gvm_username` (string): Username for GVM API authentication.
- `gvm_password` (string): Password for GVM API authentication.
- `name` (string): Name of the schedule.
- `comment` (string, optional): Description of the schedule.
- `time_zone` (string): Time zone for the schedule.
- `first_run_at` (string): First run date and time of the schedule. Format: "Month Day Year HH:MM".
- `recurrence` (dictionary): Recurrence settings for the schedule.
  - `frequency` (string): Frequency of recurrence. Valid values include `DAILY`, `WEEKLY`, `MONTHLY`.
  - `interval` (integer): Interval of recurrence.
  - `days_of_week` (list of strings, optional): Days of the week for weekly recurrence. Example: `["Mo", "Tu", "We"]`.
- `state` (string): State of the schedule. Valid values are `present` and `absent`.

#### Examples

- Create a weekly Saturday schedule:

    ```yaml
    - name: Create a weekly Saturday schedule
      gvm_schedule:
        socket_path: "/run/gvmd/gvmd.sock"
        gvm_username: "admin"
        gvm_password: "admin"
        name: "weekly_saturday_schedule"
        comment: "Weekly Saturday schedule"
        time_zone: "UTC"
        first_run_at: "Aug 12 2023 00:00"
        recurrence:
          frequency: "WEEKLY"
          interval: 1
          days_of_week:
            - "Sa"
        state: present
    ```

- Update an existing schedule:

    ```yaml
    - name: Update an existing schedule
      gvm_schedule:
        socket_path: "/run/gvmd/gvmd.sock"
        gvm_username: "admin"
        gvm_password: "admin"
        name: "weekly_saturday_schedule"
        comment: "Updated weekly Saturday schedule"
        time_zone: "UTC"
        first_run_at: "Aug 12 2023 00:00"
        recurrence:
          frequency: "WEEKLY"
          interval: 1
          days_of_week:
            - "Sa"
        state: present
    ```

- Delete a schedule:

    ```yaml
    - name: Delete a schedule
      gvm_schedule:
        socket_path: "/run/gvmd/gvmd.sock"
        gvm_username: "admin"
        gvm_password: "admin"
        name: "weekly_saturday_schedule"
        state: absent
    ```

### gvm_target

Manage GVM targets.

#### Parameters

- `socket_path` (string): Path to the GVM Unix socket. Example: `/run/gvmd/gvmd.sock`
- `gvm_username` (string): Username for GVM API authentication.
- `gvm_password` (string): Password for GVM API authentication.
- `name` (string): Name of the target.
- `comment` (string, optional): Description of the target.
- `hosts` (list of strings): List of IP addresses or hostname for the target.
- `exclude_hosts` (list of strings, optional): List of IP addresses or hostname to exclude from the target.
- `allow_simultaneous_ips` (boolean): Whether to allow simultaneous IPs.
- `port_list_name` (string): Name of the port list to use.
- `port_range` (list of dictionaries, optional): List of port ranges. Each dictionary should include `from` and `to` keys.
- `alive_test` (string): Method to test if the target is alive. Valid values include `TCP_ACK_SERVICE_PING`, `ICMP_ECHO_REQUEST`, etc.
- `reverse_lookup_only` (boolean): Whether to only use reverse lookup for the target.
- `reverse_lookup_unify` (boolean): Whether to unify reverse lookups.
- `ssh_port` (integer, optional): SSH port for the target.
- `state` (string): State of the target. Valid values are `present` and `absent`.

#### Examples

- Create a new target for a database server:

    ```yaml
    - name: Create a new target for a database server
      gvm_target:
        socket_path: "/run/gvmd/gvmd.sock"
        gvm_username: "admin"
        gvm_password: "admin"
        name: "database_server"
        comment: "Database server"
        hosts:
          - "10.116.0.2"
        exclude_hosts: []
        allow_simultaneous_ips: true
        port_list_name: "All TCP and Nmap top 100 UDP"
        port_range: []
        alive_test: "TCP_ACK_SERVICE_PING"
        reverse_lookup_only: false
        reverse_lookup_unify: false
        ssh_port: 22
        state: present
    ```

- Delete an existing target:

    ```yaml
    - name: Delete an existing target
      gvm_target:
        socket_path: "/run/gvmd/gvmd.sock"
        gvm_username: "admin"
        gvm_password: "admin"
        name: "database_server"
        state: absent
    ```

### gvm_task

The `gvm_task` module manages scan tasks in GVM.

#### Parameters

- `socket_path` (required): Path to the GVM socket.
- `gvm_username` (required): Username for GVM authentication.
- `gvm_password` (required): Password for GVM authentication.
- `name` (required): Name of the scan task.
- `comment` (optional): Comment for the scan task.
- `target_name` (required): Name of the target for the scan.
- `schedule_name` (optional): Name of the schedule for the scan.
- `scan_once` (optional): If `true`, the scan task will run only once.
- `add_result_in_assets` (optional): If `true`, results will be added to assets.
- `apply_overrides` (optional): If `true`, task configuration will be overridden.
- `min_quality_of_detection` (optional): Minimum quality of detection.
- `alterable` (optional): If `false`, the task cannot be altered.
- `auto_delete` (optional): If `true`, the task will be automatically deleted.
- `auto_delete_data` (optional): Number of days to keep data before auto-deleting.
- `scanner_name` (optional): Name of the scanner to use.
- `config_name` (optional): Name of the scan configuration to use.
- `hosts_ordering` (optional): Ordering of hosts for scanning.
- `max_concurrency_executed_nvt_per_host` (optional): Maximum number of concurrent NVTs per host.
- `max_concurrency_scanned_host` (optional): Maximum number of concurrent scanned hosts.
- `status` (required): The desired state of the task (`present` or `absent`).

#### Examples

##### Create a new database server scan task

```yaml
- name: Create a new database server scan task
  greenbone_gvm.gvm_task:
    socket_path: "/run/gvmd/gvmd.sock"
    gvm_username: "admin"
    gvm_password: "admin"
    name: "database_server_scan"
    comment: "Database server vulnerability scan"
    target_name: "database_server"
    schedule_name: "weekly_saturday_schedule"
    scan_once: false
    add_result_in_assets: true
    apply_overrides: true
    min_quality_of_detection: 70
    alterable: false
    auto_delete: true
    auto_delete_data: 5
    scanner_name: "OpenVAS Default"
    config_name: "Full and fast"
    hosts_ordering: "sequential"
    max_concurrency_executed_nvt_per_host: 4
    max_concurrency_scanned_host: 20
    status: present
```

##### Delete a task

```yaml
- name: Delete a task
  greenbone_gvm.gvm_task:
    socket_path: "/run/gvmd/gvmd.sock"
    gvm_username: "admin"
    gvm_password: "admin"
    name: "database_server_scan"
    target_name: "database_server"
    status: absent
```

### gvm_audit

The `gvm_audit` module manages audits in GVM.

#### Parameters

- `socket_path` (required): Path to the GVM socket.
- `gvm_username` (required): Username for GVM authentication.
- `gvm_password` (required): Password for GVM authentication.
- `name` (required): Name of the audit.
- `comment` (optional): Comment for the audit.
- `target_name` (required): Name of the target for the audit.
- `schedule_name` (optional): Name of the schedule for the audit.
- `scan_once` (optional): If `true`, the audit will run only once.
- `add_result_in_assets` (optional): If `true`, results will be added to assets.
- `apply_overrides` (optional): If `true`, audit configuration will be overridden.
- `min_quality_of_detection` (optional): Minimum quality of detection.
- `alterable` (optional): If `false`, the audit cannot be altered.
- `auto_delete` (optional): If `true`, the audit will be automatically deleted.
- `auto_delete_data` (optional): Number of days to keep data before auto-deleting.
- `scanner_name` (optional): Name of the scanner to use.
- `policy_config_name` (optional): Name of the policy configuration to use.
- `hosts_ordering` (optional): Ordering of hosts for auditing.
- `max_concurrency_executed_nvt_per_host` (optional): Maximum number of concurrent NVTs per host.
- `max_concurrency_scanned_host` (optional): Maximum number of concurrent scanned hosts.
- `state` (required): The desired state of the audit (`started` or `stopped`).

#### Examples

##### Create or update an audit

```yaml
- name: Create or update an audit
  greenbone_gvm.gvm_audit:
    socket_path: "/run/gvmd/gvmd.sock"
    gvm_username: "admin"
    gvm_password: "admin"
    name: "database_server_audit"
    comment: "Database server audit"
    target_name: "database_server"
    schedule_name: "monthly_schedule"
    scan_once: false
    add_result_in_assets: true
    apply_overrides: true
    min_quality_of_detection: 70
    alterable: false
    auto_delete: true
    auto_delete_data: 5
    scanner_name: "OpenVAS Default"
    policy_config_name: "EulerOS Linux Security Configuration"
    hosts_ordering: "sequential"
    max_concurrency_executed_nvt_per_host: 4
    max_concurrency_scanned_host: 4
    state: started
```

##### Delete an audit

```yaml
- name: Delete an audit
  greenbone_gvm.gvm_audit:
    socket_path: "/run/gvmd/gvmd.sock"
    gvm_username: "admin"
    gvm_password: "admin"
    name: "database_server_audit"
    target_name: "database_server"
    state: stopped
```

## License

This collection is licensed under the [MIT License](LICENSE).

## Author Information

This collection was created in 2024 by [Black-Cockpit](https://github.com/Black-Cockpit).

For more information, visit the [Ansible Galaxy page](https://galaxy.ansible.com/hasnimehdi91/greenbone_gvm).

```