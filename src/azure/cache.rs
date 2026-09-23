// ported from neboto-tui src/aws/cache.rs @ d483900
use crate::azure::resource::Resource;
use crate::azure::service::ServiceType;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Cache key: service + subscription + an optional variant discriminator
/// (the sub-tab's `JumpView::as_str()`).
///
/// neboto keys on `(service, region, variant)` because every AWS list is
/// region-scoped. Azure lists are subscription-wide and location is a
/// client-side filter, so the key is `(service, subscription, variant)`
/// and a location switch never touches the cache — which is also what
/// keeps the Storage RP's 100-list-calls-per-5-min budget intact.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    service: ServiceType,
    subscription: String,
    variant: Option<String>,
}

/// Pseudo-subscription under which tenant-scoped lists are cached.
const TENANT_SCOPE: &str = "<tenant>";

pub struct ResourceCache {
    entries: HashMap<CacheKey, CacheEntry>,
    ttl: Duration,
    /// Per-service TTL overrides from config (`cache_ttls`). Checked before
    /// the built-in defaults in `effective_ttl`.
    ttl_overrides: HashMap<ServiceType, Duration>,
}

struct CacheEntry {
    resources: Vec<Box<dyn Resource>>,
    timestamp: Instant,
}

impl ResourceCache {
    pub fn new(ttl: Duration, ttl_overrides: HashMap<ServiceType, Duration>) -> Self {
        Self {
            entries: HashMap::new(),
            ttl,
            ttl_overrides,
        }
    }

    fn key(service: &ServiceType, subscription: &str, variant: Option<&str>) -> CacheKey {
        CacheKey {
            service: *service,
            subscription: if service.is_tenant_scoped(variant) {
                TENANT_SCOPE.to_string()
            } else {
                subscription.to_string()
            },
            variant: variant.map(str::to_string),
        }
    }

    /// Per-service freshness window: config override first, then the built-in
    /// default.
    fn effective_ttl(&self, service: &ServiceType) -> Duration {
        self.ttl_overrides
            .get(service)
            .copied()
            .unwrap_or(self.ttl)
    }

    pub fn get(
        &self,
        service: &ServiceType,
        subscription: &str,
        variant: Option<&str>,
    ) -> Option<Vec<Box<dyn Resource>>> {
        let key = Self::key(service, subscription, variant);
        let ttl = self.effective_ttl(service);
        self.entries.get(&key).and_then(|entry| {
            if entry.timestamp.elapsed() < ttl {
                Some(entry.resources.to_vec())
            } else {
                None
            }
        })
    }

    pub fn insert(
        &mut self,
        service: ServiceType,
        subscription: &str,
        variant: Option<String>,
        resources: Vec<Box<dyn Resource>>,
    ) {
        let key = Self::key(&service, subscription, variant.as_deref());
        self.entries.insert(
            key,
            CacheEntry {
                resources,
                timestamp: Instant::now(),
            },
        );
    }

    /// Borrow the live (within-TTL) entry for this key without cloning — the
    /// `@all` cross-service search scans every cached list on each keystroke
    /// and only clones what it keeps.
    pub fn get_ref(
        &self,
        service: &ServiceType,
        subscription: &str,
        variant: Option<&str>,
    ) -> Option<&[Box<dyn Resource>]> {
        let key = Self::key(service, subscription, variant);
        let ttl = self.effective_ttl(service);
        self.entries.get(&key).and_then(|entry| {
            (entry.timestamp.elapsed() < ttl).then_some(entry.resources.as_slice())
        })
    }

    /// Age of the live (within-TTL) cache entry for this key, if any. Lets the
    /// UI surface how old the data on screen is ("updated 3m ago").
    pub fn age(
        &self,
        service: &ServiceType,
        subscription: &str,
        variant: Option<&str>,
    ) -> Option<Duration> {
        let key = Self::key(service, subscription, variant);
        let ttl = self.effective_ttl(service);
        self.entries.get(&key).and_then(|entry| {
            let age = entry.timestamp.elapsed();
            (age < ttl).then_some(age)
        })
    }

    pub fn invalidate(&mut self, service: &ServiceType, subscription: &str, variant: Option<&str>) {
        let key = Self::key(service, subscription, variant);
        self.entries.remove(&key);
    }
}
