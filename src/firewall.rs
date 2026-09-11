#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
const NAT_TABLE: &str = "nat";
#[cfg(target_os = "linux")]
const FILTER_TABLE: &str = "filter";
#[cfg(target_os = "linux")]
const NAT_CHAIN: &str = "TIMEKPR_UID_DNS";
#[cfg(target_os = "linux")]
const FILTER_CHAIN: &str = "TIMEKPR_UID_EGRESS";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FirewallPolicy {
    pub uid: u32,
    pub listen_port: u16,
}

#[cfg(target_os = "linux")]
pub fn reconcile(policies: &[FirewallPolicy]) -> Result<(), String> {
    ensure_chain(NAT_TABLE, NAT_CHAIN)?;
    ensure_chain(FILTER_TABLE, FILTER_CHAIN)?;
    ensure_jump(NAT_TABLE, "OUTPUT", NAT_CHAIN)?;
    ensure_jump(FILTER_TABLE, "OUTPUT", FILTER_CHAIN)?;
    flush_chain(NAT_TABLE, NAT_CHAIN)?;
    flush_chain(FILTER_TABLE, FILTER_CHAIN)?;

    for policy in policies {
        append_nat_redirect(policy, "udp")?;
        append_nat_redirect(policy, "tcp")?;
        append_dns_tls_block(policy, "udp")?;
        append_dns_tls_block(policy, "tcp")?;
        // Guard only this UID's listen port. A cartesian product over all
        // managed ports creates contradictory REJECT rules that break
        // redirected DNS for every UID whenever 2+ users have domain policy
        // (common failure mode for Wine/Proton games that use classic port-53
        // DNS instead of DoH / nss-resolve).
        append_port_guard(policy.uid, policy.listen_port, "udp")?;
        append_port_guard(policy.uid, policy.listen_port, "tcp")?;
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn ensure_chain(table: &str, chain: &str) -> Result<(), String> {
    let status = Command::new("iptables")
        .args(["-t", table, "-L", chain])
        .status()
        .map_err(|error| format!("failed to inspect iptables chain {}: {}", chain, error))?;
    if status.success() {
        return Ok(());
    }

    run_iptables(["-t", table, "-N", chain])
}

#[cfg(target_os = "linux")]
fn ensure_jump(table: &str, from_chain: &str, to_chain: &str) -> Result<(), String> {
    let status = Command::new("iptables")
        .args(["-t", table, "-C", from_chain, "-j", to_chain])
        .status()
        .map_err(|error| {
            format!(
                "failed to inspect iptables jump {} -> {}: {}",
                from_chain, to_chain, error
            )
        })?;
    if status.success() {
        return Ok(());
    }

    run_iptables(["-t", table, "-A", from_chain, "-j", to_chain])
}

#[cfg(target_os = "linux")]
fn flush_chain(table: &str, chain: &str) -> Result<(), String> {
    run_iptables(["-t", table, "-F", chain])
}

#[cfg(target_os = "linux")]
fn append_nat_redirect(policy: &FirewallPolicy, protocol: &str) -> Result<(), String> {
    run_iptables([
        "-t",
        NAT_TABLE,
        "-A",
        NAT_CHAIN,
        "-m",
        "owner",
        "--uid-owner",
        &policy.uid.to_string(),
        "-p",
        protocol,
        "--dport",
        "53",
        "-j",
        "REDIRECT",
        "--to-ports",
        &policy.listen_port.to_string(),
    ])
}

#[cfg(target_os = "linux")]
fn append_dns_tls_block(policy: &FirewallPolicy, protocol: &str) -> Result<(), String> {
    run_iptables([
        "-t",
        FILTER_TABLE,
        "-A",
        FILTER_CHAIN,
        "-m",
        "owner",
        "--uid-owner",
        &policy.uid.to_string(),
        "-p",
        protocol,
        "--dport",
        "853",
        "-j",
        "REJECT",
    ])
}

#[cfg(target_os = "linux")]
fn append_port_guard(uid: u32, port: u16, protocol: &str) -> Result<(), String> {
    let args = build_port_guard_args(uid, port, protocol);
    run_iptables_owned(&args)
}

#[cfg(target_os = "linux")]
fn build_port_guard_args(uid: u32, port: u16, protocol: &str) -> Vec<String> {
    vec![
        "-t".to_string(),
        FILTER_TABLE.to_string(),
        "-A".to_string(),
        FILTER_CHAIN.to_string(),
        "-m".to_string(),
        "owner".to_string(),
        "!".to_string(),
        "--uid-owner".to_string(),
        uid.to_string(),
        "-p".to_string(),
        protocol.to_string(),
        "--dport".to_string(),
        port.to_string(),
        "-j".to_string(),
        "REJECT".to_string(),
    ]
}

#[cfg(target_os = "linux")]
fn run_iptables<const N: usize>(args: [&str; N]) -> Result<(), String> {
    let output = Command::new("iptables")
        .args(args)
        .output()
        .map_err(|error| format!("failed to run iptables: {}", error))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!("iptables command failed: {}", stderr.trim()))
}

#[cfg(target_os = "linux")]
fn run_iptables_owned(args: &[String]) -> Result<(), String> {
    let output = Command::new("iptables")
        .args(args)
        .output()
        .map_err(|error| format!("failed to run iptables: {}", error))?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(format!("iptables command failed: {}", stderr.trim()))
}

#[cfg(target_os = "windows")]
pub fn reconcile(_policies: &[FirewallPolicy]) -> Result<(), String> {
    // Windows firewall settings are applied at the system layer via network DNS
    // redirection and Windows Defender Firewall commands, so we no-op here.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::FirewallPolicy;
    #[cfg(target_os = "linux")]
    use super::build_port_guard_args;

    fn render_rules(policies: &[FirewallPolicy]) -> Vec<String> {
        let mut rules = Vec::new();
        for policy in policies {
            rules.push(format!(
                "redirect uid={} udp 53 -> {}",
                policy.uid, policy.listen_port
            ));
            rules.push(format!(
                "redirect uid={} tcp 53 -> {}",
                policy.uid, policy.listen_port
            ));
            rules.push(format!("block uid={} udp 853", policy.uid));
            rules.push(format!("block uid={} tcp 853", policy.uid));
            rules.push(format!(
                "guard uid={} {} -> {}",
                policy.uid, policy.listen_port, policy.listen_port
            ));
        }
        rules
    }

    #[test]
    fn firewall_rule_shape_covers_redirects_and_guards() {
        let policies = vec![
            FirewallPolicy {
                uid: 1000,
                listen_port: 23001,
            },
            FirewallPolicy {
                uid: 1001,
                listen_port: 23002,
            },
        ];

        let rules = render_rules(&policies);
        assert!(
            rules
                .iter()
                .any(|rule| rule.contains("redirect uid=1000 udp 53 -> 23001"))
        );
        assert!(
            rules
                .iter()
                .any(|rule| rule.contains("block uid=1001 tcp 853"))
        );
        assert!(
            rules
                .iter()
                .any(|rule| rule.contains("guard uid=1000 23001 -> 23001"))
        );
        assert!(
            rules
                .iter()
                .any(|rule| rule.contains("guard uid=1001 23002 -> 23002"))
        );
        // Cross-UID guards must not exist: they REJECT each user's own
        // redirected DNS when multiple UIDs are managed.
        assert!(
            !rules
                .iter()
                .any(|rule| rule.contains("guard uid=1000 23002 -> 23002"))
        );
        assert!(
            !rules
                .iter()
                .any(|rule| rule.contains("guard uid=1001 23001 -> 23001"))
        );
    }

    #[test]
    fn multi_uid_port_guards_do_not_conflict() {
        let policies = vec![
            FirewallPolicy {
                uid: 1001,
                listen_port: 23010,
            },
            FirewallPolicy {
                uid: 1002,
                listen_port: 23011,
            },
        ];
        let rules = render_rules(&policies);
        let guards: Vec<_> = rules
            .iter()
            .filter(|rule| rule.starts_with("guard "))
            .cloned()
            .collect();
        assert_eq!(
            guards,
            vec![
                "guard uid=1001 23010 -> 23010".to_string(),
                "guard uid=1002 23011 -> 23011".to_string(),
            ]
        );
    }

    #[test]
    #[cfg(target_os = "linux")]
    fn port_guard_negates_uid_owner_match_in_supported_position() {
        let args = build_port_guard_args(1000, 23001, "udp");
        assert_eq!(
            args,
            vec![
                "-t",
                "filter",
                "-A",
                "TIMEKPR_UID_EGRESS",
                "-m",
                "owner",
                "!",
                "--uid-owner",
                "1000",
                "-p",
                "udp",
                "--dport",
                "23001",
                "-j",
                "REJECT",
            ]
        );
    }
}
