# GeoIP Filter Module

A Ferron server module that blocks or allows HTTP requests based on the client's country using API external lookup.

## Features

- **Whitelist mode**: Allow only specified countries
- **Blacklist mode**: Block specified countries
- **Unknown IP handling**: Configurable behavior for IPs not found in database

## Configuration

```
geoip_filter mode="whitelist" countries="VN,US,JP,KR" allow_unknown=#false api_url="http://127.0.0.1/check-ip?ip="
```

### Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `mode` | string | Yes | `whitelist` or `blacklist` |
| `countries` | string | Yes | Comma-separated country codes (ISO 3166-1 alpha-2) |
| `allow_unknown` | boolean | No | Allow IPs with unknown country (default: `false`) |
| `api_url` | string | Yes | API to lookup IP |

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

### Example 1: Allow only Vietnam and USA
```
geoip_filter mode="whitelist" countries ="VN,US" allow_unknown=#false api_url="http://127.0.0.1/check-ip?ip="
```

### Example 2: Block specific countries
```
geoip_filter mode="blacklist" countries="CN,RU,KP" allow_unknown=#true api_url="http://127.0.0.1/check-ip?ip="
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
- For best security, use `allow_unknown: false` to block unknown IPs