use std::collections::HashSet;
use std::error::Error;
use std::net::IpAddr;
use std::sync::Arc;

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

/// GeoIP filtering modes
#[derive(Debug, Clone, PartialEq, Eq)]
enum GeoIPMode {
  /// Allow only countries in the list (whitelist mode)
  Whitelist,
  /// Deny countries in the list (blacklist mode)
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

/// Module loader for GeoIP blocking
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
      // Cache based on geoip_filter property
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

          // Read mode from props (whitelist or blacklist)
          let mode_str = geoip_entry
            .and_then(|e| e.props.get("mode"))
            .and_then(|v| v.as_str())
            .ok_or("Missing geoip_filter mode configuration")?;
          let mode = GeoIPMode::from_str(mode_str)?;

          // Read country list from props
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

          // Read allow_unknown flag (default: false for security)
          let allow_unknown = geoip_entry
            .and_then(|e| e.props.get("allow_unknown"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

          // Read MaxMind DB path from props
          let db_path = geoip_entry
            .and_then(|e| e.props.get("db_path"))
            .and_then(|v| v.as_str())
            .ok_or("Missing geoip_filter db_path configuration")?;

          // Load MaxMind database
          let reader = Reader::open_readfile(db_path)
            .map_err(|e| format!("Failed to open MaxMind database at {}: {}", db_path, e))?;

          Ok(Arc::new(GeoIPModule {
            mode,
            countries,
            allow_unknown,
            reader: Arc::new(reader),
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
        // Validate boolean value
        if entry.values.len() != 1 || !entry.values[0].is_bool() {
          return Err("The `geoip_filter` configuration property must have exactly one boolean value".into());
        }

        // Validate mode property
        if let Some(mode_val) = entry.props.get("mode") {
          if let Some(mode_str) = mode_val.as_str() {
            GeoIPMode::from_str(mode_str)?;
          } else {
            return Err("The `mode` property must be a string".into());
          }
        } else {
          return Err("The `mode` property is required in geoip_filter configuration".into());
        }

        // Validate countries property
        if let Some(countries_val) = entry.props.get("countries") {
          if !countries_val.is_string() {
            return Err("The `countries` property must be a string".into());
          }
        } else {
          return Err("The `countries` property is required in geoip_filter configuration".into());
        }

        // Validate allow_unknown property (optional)
        if let Some(allow_unknown_val) = entry.props.get("allow_unknown") {
          if !allow_unknown_val.is_bool() {
            return Err("The `allow_unknown` property must be a boolean".into());
          }
        }

        // Validate db_path property
        if let Some(db_path_val) = entry.props.get("db_path") {
          if !db_path_val.is_string() {
            return Err("The `db_path` property must be a string".into());
          }
        } else {
          return Err("The `db_path` property is required in geoip_filter configuration".into());
        }
      }
    }
    Ok(())
  }
}

/// Main GeoIP blocking module
struct GeoIPModule {
  mode: GeoIPMode,
  countries: HashSet<String>,
  allow_unknown: bool,
  reader: Arc<Reader<Vec<u8>>>,
}

impl Module for GeoIPModule {
  fn get_module_handlers(&self) -> Box<dyn ModuleHandlers> {
    Box::new(GeoIPModuleHandlers {
      mode: self.mode.clone(),
      countries: self.countries.clone(),
      allow_unknown: self.allow_unknown,
      reader: Arc::clone(&self.reader),
    })
  }
}

/// Request handlers for GeoIP blocking
struct GeoIPModuleHandlers {
  mode: GeoIPMode,
  countries: HashSet<String>,
  allow_unknown: bool,
  reader: Arc<Reader<Vec<u8>>>,
}

impl GeoIPModuleHandlers {
  /// Check if this IP should be blocked based on country and configuration
  fn should_block(&self, ip: IpAddr) -> bool {
    // Lookup country code from MaxMind DB
    let country_code = self.lookup_country(ip);

    match country_code {
      Some(code) => {
        // Country found in database
        match &self.mode {
          GeoIPMode::Whitelist => {
            // Block if NOT in whitelist
            !self.countries.contains(&code)
          }
          GeoIPMode::Blacklist => {
            // Block if IN blacklist
            self.countries.contains(&code)
          }
        }
      }
      None => {
        // Country unknown (not found in database)
        // Block if allow_unknown is false
        !self.allow_unknown
      }
    }
  }

  /// Lookup country code from IP address using MaxMind database
  fn lookup_country(&self, ip: IpAddr) -> Option<String> {
    // Use GeoIP2-Country database format with new API
    self
      .reader
      .lookup(ip)
      .ok()
      .and_then(|result| result.decode::<maxminddb::geoip2::City>().ok())
      .flatten()
      .and_then(|country_data| country_data.country.iso_code.map(|c| c.to_uppercase()))
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
    // Get IP address from socket data
    let ip = socket_data.remote_addr.ip().to_canonical();

    // Check if should block
    if self.should_block(ip) {
      let country = self.lookup_country(ip).unwrap_or_else(|| "Unknown".to_string());

      // Log blocking information
      error_logger
        .log(&format!(
          "GeoIP blocked request from IP {} (Country: {}, Mode: {:?}, AllowUnknown: {})",
          ip, country, self.mode, self.allow_unknown
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
