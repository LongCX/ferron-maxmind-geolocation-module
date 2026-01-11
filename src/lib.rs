use std::collections::HashSet;
use std::error::Error;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;
use parking_lot::Mutex;

use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use hyper::{Request, StatusCode};
use maxminddb::Reader;

use ferron_common::config::ServerConfiguration;
use ferron_common::logging::ErrorLogger;
use ferron_common::modules::{Module, ModuleHandlers, ModuleLoader, ResponseData, SocketData};
use ferron_common::util::ModuleCache;
use ferron_common::{get_entries_for_validation, get_entry};

#[derive(Debug, Clone, PartialEq, Eq)]
enum GeoIPMode {
  Whitelist,
  Blacklist,
}

impl GeoIPMode {
  fn from_str(s: &str) -> Result<Self, Box<dyn Error + Send + Sync>> {
    match s.to_lowercase().as_str() {
      "whitelist" => Ok(GeoIPMode::Whitelist),
      "blacklist" => Ok(GeoIPMode::Blacklist),
      _ => Err(format!("Invalid GeoIP mode: {}. Valid modes are: whitelist, blacklist", s).into()),
    }
  }
}
struct CacheEntry {
  country: Option<String>,
  inserted_at: Instant,
}

pub struct GeoIPModuleLoader {
  cache: ModuleCache<GeoIPModule>,
}

impl Default for GeoIPModuleLoader {
  fn default() -> Self {
    Self::new()
  }
}

impl GeoIPModuleLoader {
  pub fn new() -> Self {
    Self {
      cache: ModuleCache::new(vec!["geoip_filter"]),
    }
  }
}

impl ModuleLoader for GeoIPModuleLoader {
  fn load_module(
    &mut self,
    config: &ServerConfiguration,
    _global_config: Option<&ServerConfiguration>,
    _secondary_runtime: &tokio::runtime::Runtime,
  ) -> Result<Arc<dyn Module + Send + Sync>, Box<dyn Error + Send + Sync>> {
    Ok(
      self
        .cache
        .get_or_init::<_, Box<dyn Error + Send + Sync>>(config, |config| {
          let geoip_entry = get_entry!("geoip_filter", config);

          let mode_str = geoip_entry
            .and_then(|e| e.props.get("mode"))
            .and_then(|v| v.as_str())
            .ok_or("Missing geoip_filter mode configuration")?;
          let mode = GeoIPMode::from_str(mode_str)?;

          let countries_str = geoip_entry
            .and_then(|e| e.props.get("countries"))
            .and_then(|v| v.as_str())
            .ok_or("Missing geoip_filter countries configuration")?;

          let countries: HashSet<String> = countries_str
            .split(',')
            .map(|s| s.trim().to_uppercase())
            .filter(|s| !s.is_empty())
            .collect();

          if countries.is_empty() {
            return Err("geoip_filter countries must contain at least one country code".into());
          }

          let allow_unknown = geoip_entry
            .and_then(|e| e.props.get("allow_unknown"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

          let db_path = geoip_entry
            .and_then(|e| e.props.get("db_path"))
            .and_then(|v| v.as_str())
            .ok_or("Missing geoip_filter db_path configuration")?;

          let reader = Reader::open_readfile(db_path)
            .map_err(|e| format!("Failed to open MaxMind database at {}: {}", db_path, e))?;

          let cache_size = geoip_entry
            .and_then(|e| e.props.get("cache_size"))
            .and_then(|v| v.as_i128())
            .unwrap_or(10_000)
            .max(1) as usize;

          let cache_ttl_secs = geoip_entry
            .and_then(|e| e.props.get("cache_ttl"))
            .and_then(|v| v.as_i128())
            .unwrap_or(300)
            .max(1) as u64;
          let cache_ttl = Duration::from_secs(cache_ttl_secs);

          let cache = LruCache::new(NonZeroUsize::new(cache_size.max(1)).unwrap());

          Ok(Arc::new(GeoIPModule {
            mode,
            countries: Arc::new(countries),
            allow_unknown,
            reader: Arc::new(reader),
            cache: Arc::new(Mutex::new(cache)),
            cache_ttl,
          }))
        })?,
    )
  }

  fn get_requirements(&self) -> Vec<&'static str> {
    vec!["geoip_filter"]
  }

  fn validate_configuration(
    &self,
    config: &ServerConfiguration,
    used_properties: &mut std::collections::HashSet<String>,
  ) -> Result<(), Box<dyn Error + Send + Sync>> {
    if let Some(entries) = get_entries_for_validation!("geoip_filter", config, used_properties) {
      for entry in &entries.inner {
        if entry.values.len() != 1 || !entry.values[0].is_bool() {
          return Err(anyhow::anyhow!(
            "The `geoip_filter` configuration property must have exactly one boolean value"
          ))?;
        }

        if let Some(mode_val) = entry.props.get("mode") {
          if let Some(mode_str) = mode_val.as_str() {
            GeoIPMode::from_str(mode_str)?;
          } else {
            return Err(anyhow::anyhow!("The `mode` property must be a string"))?;
          }
        } else {
          return Err(anyhow::anyhow!(
            "The `mode` property is required in geoip_filter configuration"
          ))?;
        }

        if let Some(countries_val) = entry.props.get("countries") {
          if !countries_val.is_string() {
            return Err(anyhow::anyhow!("The `countries` property must be a string"))?;
          }
        } else {
          return Err(anyhow::anyhow!(
            "The `countries` property is required in geoip_filter configuration"
          ))?;
        }

        if let Some(allow_unknown_val) = entry.props.get("allow_unknown") {
          if !allow_unknown_val.is_bool() {
            return Err(anyhow::anyhow!("The `allow_unknown` property must be a boolean"))?;
          }
        }

        if let Some(db_path_val) = entry.props.get("db_path") {
          if !db_path_val.is_string() {
            return Err(anyhow::anyhow!("The `db_path` property must be a string"))?;
          }
        } else {
          return Err(anyhow::anyhow!(
            "The `db_path` property is required in geoip_filter configuration"
          ))?;
        }

        if let Some(cache_size_val) = entry.props.get("cache_size") {
          if let Some(v) = cache_size_val.as_i128() {
            if v < 1 {
              return Err(anyhow::anyhow!("`cache_size` must be a positive integer (>= 1)"))?;
            }
          } else {
            return Err(anyhow::anyhow!("`cache_size` must be an integer"))?;
          }
        }

        if let Some(cache_ttl_val) = entry.props.get("cache_ttl") {
          if let Some(v) = cache_ttl_val.as_i128() {
            if v < 1 {
              return Err(anyhow::anyhow!(
                "`cache_ttl` must be a positive integer (>= 1, seconds)"
              ))?;
            }
          } else {
            return Err(anyhow::anyhow!("`cache_ttl` must be an integer (seconds)"))?;
          }
        }
      }
    }
    Ok(())
  }
}

struct GeoIPModule {
  mode: GeoIPMode,
  countries: Arc<HashSet<String>>,
  allow_unknown: bool,
  reader: Arc<Reader<Vec<u8>>>,
  cache: Arc<Mutex<LruCache<IpAddr, CacheEntry>>>,
  cache_ttl: Duration,
}

impl Module for GeoIPModule {
  fn get_module_handlers(&self) -> Box<dyn ModuleHandlers> {
    Box::new(GeoIPModuleHandlers {
      mode: self.mode.clone(),
      countries: Arc::clone(&self.countries),
      allow_unknown: self.allow_unknown,
      reader: Arc::clone(&self.reader),
      cache: Arc::clone(&self.cache),
      cache_ttl: self.cache_ttl,
    })
  }
}

struct GeoIPModuleHandlers {
  mode: GeoIPMode,
  countries: Arc<HashSet<String>>,
  allow_unknown: bool,
  reader: Arc<Reader<Vec<u8>>>,
  cache: Arc<Mutex<LruCache<IpAddr, CacheEntry>>>,
  cache_ttl: Duration,
}

impl GeoIPModuleHandlers {
  fn lookup_country_cached(&self, ip: IpAddr) -> Option<String> {
    let now = Instant::now();
    let mut cache = self.cache.lock();
    if let Some(entry) = cache.get(&ip) {
      if now.duration_since(entry.inserted_at) <= self.cache_ttl {
        return entry.country.clone();
      }
      cache.pop(&ip);
    }

    let country = self
      .reader
      .lookup(ip)
      .ok()
      .and_then(|r| r.decode::<maxminddb::geoip2::City>().ok())
      .flatten()
      .and_then(|c| c.country.iso_code.map(|c| c.to_ascii_uppercase()));

    self.cache.lock().put(
      ip,
      CacheEntry {
        country: country.clone(),
        inserted_at: now,
      },
    );

    country
  }
  fn should_block(&self, country: Option<&str>) -> bool {
    match country {
      Some(code) => match self.mode {
        GeoIPMode::Whitelist => !self.countries.contains(code),
        GeoIPMode::Blacklist => self.countries.contains(code),
      },
      None => !self.allow_unknown,
    }
  }
}

#[async_trait(?Send)]
impl ModuleHandlers for GeoIPModuleHandlers {
  async fn request_handler(
    &mut self,
    request: Request<BoxBody<Bytes, std::io::Error>>,
    _config: &ServerConfiguration,
    socket_data: &SocketData,
    error_logger: &ErrorLogger,
  ) -> Result<ResponseData, Box<dyn Error + Send + Sync>> {
    let ip = socket_data.remote_addr.ip().to_canonical();

    let country = self.lookup_country_cached(ip);

    if self.should_block(country.as_deref()) {
      error_logger
        .log(&format!(
          "GeoIP blocked request from IP {} (Country: {}, Mode: {:?}, AllowUnknown: {})",
          ip,
          country.as_deref().unwrap_or("Unknown"),
          self.mode,
          self.allow_unknown
        ))
        .await;

      Ok(ResponseData {
        request: Some(request),
        response: None,
        response_status: Some(StatusCode::FORBIDDEN),
        response_headers: None,
        new_remote_address: None,
      })
    } else {
      Ok(ResponseData {
        request: Some(request),
        response: None,
        response_status: None,
        response_headers: None,
        new_remote_address: None,
      })
    }
  }
}
