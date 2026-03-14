//! DNS-IP association tracker.
//!
//! Records IP addresses resolved by `getaddrinfo`/`gethostbyname` and maps
//! them back to the original domain name. When `connect()` targets a resolved
//! IP, the tracker provides the domain for policy evaluation.

use std::collections::HashMap;
use std::sync::OnceLock;

use super::fork_mutex::ForkSafeMutex;

/// Maximum number of IP→domain entries before LRU eviction kicks in.
const MAX_ENTRIES: usize = 4096;

static DNS_TRACKER: OnceLock<DnsTracker> = OnceLock::new();

/// Get the global DNS tracker instance.
pub fn dns_tracker() -> &'static DnsTracker {
    DNS_TRACKER.get_or_init(DnsTracker::new)
}

/// Tracks IP→domain associations from DNS resolution calls.
pub struct DnsTracker {
    entries: ForkSafeMutex<DnsCache>,
}

#[derive(Default)]
struct DnsCache {
    /// IP address → domain name (e.g., "93.184.216.34" → "example.com")
    ip_to_domain: HashMap<String, String>,
    /// IP address → insertion order for LRU eviction
    ip_to_order: HashMap<String, u64>,
    /// Monotonic counter for LRU ordering
    counter: u64,
}

impl DnsTracker {
    fn new() -> Self {
        Self {
            entries: ForkSafeMutex::new(DnsCache::default()),
        }
    }

    /// Record a DNS resolution: `domain` resolved to `ip`.
    ///
    /// Called from `on_leave` hooks for `getaddrinfo`/`gethostbyname` after
    /// parsing the result structures.
    pub fn record(&self, domain: &str, ip: &str) {
        let Ok(mut cache) = self.entries.lock() else {
            return;
        };

        // Evict oldest entries if at capacity
        if cache.ip_to_domain.len() >= MAX_ENTRIES && !cache.ip_to_domain.contains_key(ip) {
            // Find the entry with the smallest order value
            if let Some(oldest_ip) = cache
                .ip_to_order
                .iter()
                .min_by_key(|(_, &order)| order)
                .map(|(ip, _)| ip.clone())
            {
                cache.ip_to_domain.remove(&oldest_ip);
                cache.ip_to_order.remove(&oldest_ip);
            }
        }

        cache.counter += 1;
        let order = cache.counter;
        cache
            .ip_to_domain
            .insert(ip.to_string(), domain.to_string());
        cache.ip_to_order.insert(ip.to_string(), order);
    }

    /// Look up the domain name for a given IP address.
    ///
    /// Returns `Some("example.com")` if the IP was previously resolved via DNS.
    pub fn lookup(&self, ip: &str) -> Option<String> {
        let Ok(cache) = self.entries.lock() else {
            return None;
        };
        cache.ip_to_domain.get(ip).cloned()
    }

    /// Clear the DNS cache after fork.
    ///
    /// Child processes start with a clean cache — DNS associations from the
    /// parent are not relevant and the underlying HashMap may be in an
    /// inconsistent state if the mutex was held at fork time.
    pub fn mark_forked(&self) {
        self.entries.mark_forked();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a fresh DnsTracker for testing (not the global singleton).
    fn make_tracker() -> DnsTracker {
        DnsTracker::new()
    }

    #[test]
    fn test_dns_tracker_record_and_lookup() {
        let t = make_tracker();
        t.record("example.com", "93.184.216.34");
        assert_eq!(t.lookup("93.184.216.34"), Some("example.com".to_string()));
        assert_eq!(t.lookup("1.2.3.4"), None);
    }

    #[test]
    fn test_dns_tracker_overwrites_domain_for_same_ip() {
        let t = make_tracker();
        t.record("old.com", "1.2.3.4");
        t.record("new.com", "1.2.3.4");
        assert_eq!(t.lookup("1.2.3.4"), Some("new.com".to_string()));
    }

    #[test]
    fn test_dns_tracker_multiple_ips_same_domain() {
        let t = make_tracker();
        t.record("example.com", "93.184.216.34");
        t.record("example.com", "93.184.216.35");
        assert_eq!(t.lookup("93.184.216.34"), Some("example.com".to_string()));
        assert_eq!(t.lookup("93.184.216.35"), Some("example.com".to_string()));
    }

    #[test]
    fn test_dns_tracker_lru_eviction() {
        let t = make_tracker();
        // Fill to MAX_ENTRIES
        for i in 0..MAX_ENTRIES {
            t.record("domain.com", &format!("10.0.{}.{}", i / 256, i % 256));
        }
        // First entry should still exist
        assert_eq!(t.lookup("10.0.0.0"), Some("domain.com".to_string()));

        // Add one more — should evict the oldest (10.0.0.0)
        t.record("new.com", "192.168.1.1");
        assert_eq!(t.lookup("10.0.0.0"), None);
        assert_eq!(t.lookup("192.168.1.1"), Some("new.com".to_string()));
    }

    #[test]
    fn test_dns_tracker_mark_forked_clears_cache() {
        let t = make_tracker();
        t.record("example.com", "93.184.216.34");
        assert!(t.lookup("93.184.216.34").is_some());

        t.mark_forked();
        assert_eq!(t.lookup("93.184.216.34"), None);
    }
}
