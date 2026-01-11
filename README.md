# GeoIP Filter Module

A Ferron server module that blocks or allows HTTP requests based on the client's country using MaxMind GeoIP2 database.

## Features

- **Whitelist mode**: Allow only specified countries
- **Blacklist mode**: Block specified countries
- **Unknown IP handling**: Configurable behavior for IPs not found in database
- **MaxMind GeoIP2**: Uses industry-standard geolocation database
- **LRU cache**: High-performance in-memory cache for IP lookups
- **Cache TTL**: Automatic cache expiration to keep data fresh

## Configuration

```
geoip_filter mode="whitelist" countries="VN,US,JP,KR" allow_unknown=#false db_path="/path/to/GeoLite2-Country.mmdb"
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `mode` | string | Yes | `whitelist` or `blacklist` |
| `countries` | string | Yes | Comma-separated country codes (ISO 3166-1 alpha-2) |
| `allow_unknown` | boolean | No | Allow IPs with unknown country (default: `false`) |
| `db_path` | string | Yes | Path to MaxMind GeoIP2-Country database file |
| `cache_size` | integer | No | Maximum number of IPs stored in cache (default: `10000`) |
| `cache_ttl` | integer | No | Cache entry TTL in seconds (default: `300`) |

## Modes

### Whitelist Mode
- **Allow**: Countries in the list
- **Block**: All other countries

### Blacklist Mode
- **Block**: Countries in the list
- **Allow**: All other countries

### Unknown IP Handling
- `allow_unknown: true` - Allow IPs not found in database
- `allow_unknown: false` - Block IPs not found in database (recommended)

## Examples

### Example 1: Allow only Vietnam and USA (with cache)
```
geoip_filter mode="whitelist" countries ="VN,US" allow_unknown=#false db_path="/etc/ferron/GeoLite2-Country.mmdb" cache_size=20000 cache_ttl=600
```

### Example 2: Block specific countries
```
geoip_filter mode="blacklist" countries="CN,RU,KP" allow_unknown=#true db_path="/etc/ferron/GeoLite2-Country.mmdb"
```

## MaxMind Database

### Download GeoLite2-Country Database

1. Sign up for a free MaxMind account at https://www.maxmind.com/en/geolite2/signup
2. Download GeoLite2-Country database in MMDB format
3. Place the `.mmdb` file on your server
4. Update `db_path` in configuration

## Dependencies

Add to `Cargo.toml`:

```toml
[dependencies]
maxminddb = "0.27"
```

## Response

When a request is blocked:
- **HTTP Status**: `403 Forbidden`
- **Response Body**: Inherited from the Ferron server

## Logging

Blocked requests are logged with details:
```
GeoIP blocked request from IP 1.2.3.4 (Country: CN, Mode: Whitelist, AllowUnknown: false)
```

## Country Codes

Use ISO 3166-1 alpha-2 country codes (2 letters):
- `VN` - Vietnam
- `US` - United States
- `JP` - Japan
- `CN` - China
- `GB` - United Kingdom
- etc.

Full list: https://en.wikipedia.org/wiki/ISO_3166-1_alpha-2

## Notes

- Country codes are case-insensitive (converted to uppercase internally)
- Whitespace in country list is automatically trimmed
- Database is loaded once at startup and cached in memory
- Cache greatly improves performance under high traffic
- For best security, use `allow_unknown: false` to block unknown IPs