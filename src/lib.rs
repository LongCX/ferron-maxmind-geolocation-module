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
      _ => Err(anyhow::anyhow!(
        "Invalid GeoIP mode: {}. Valid modes are: whitelist, blacklist",
        s
      ))?,
    }
  }
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
            .ok_or("Missing geoip_filter 'mode' configuration")?;
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
            return Err(anyhow::anyhow!(
              "geoip_filter countries must contain at least one country code"
            ))?;
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
            .map_err(|e| anyhow::anyhow!("Failed to open MaxMind database at {}: {}", db_path, e))?;

          Ok(Arc::new(GeoIPModule {
            mode,
            countries: Arc::new(countries),
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
          let countries_str = countries_val
            .as_str()
            .ok_or("The `countries` property must be a string")?;

          for country in countries_str.split(',') {
            let country = country.trim().to_uppercase();
            if !country.is_empty() && (country.len() != 2 || !country.chars().all(|c| c.is_ascii_alphabetic())) {
              return Err(anyhow::anyhow!(
                "Invalid country code '{}'. Must be 2-letter ISO 3166-1 alpha-2 code",
                country
              ))?;
            }
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
}

impl Module for GeoIPModule {
  fn get_module_handlers(&self) -> Box<dyn ModuleHandlers> {
    Box::new(GeoIPModuleHandlers {
      mode: self.mode.clone(),
      countries: Arc::clone(&self.countries),
      allow_unknown: self.allow_unknown,
      reader: Arc::clone(&self.reader),
    })
  }
}

struct GeoIPModuleHandlers {
  mode: GeoIPMode,
  countries: Arc<HashSet<String>>,
  allow_unknown: bool,
  reader: Arc<Reader<Vec<u8>>>,
}

impl GeoIPModuleHandlers {
  fn lookup_country(&self, ip: IpAddr) -> Option<String> {
    let country = self
      .reader
      .lookup(ip)
      .ok()?
      .decode::<maxminddb::geoip2::City>()
      .ok()?
      .and_then(|c| c.country.iso_code.map(|c| c.to_ascii_uppercase()));

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

    let country = self.lookup_country(ip);

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
