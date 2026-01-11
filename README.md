**Configuration example:**

```kdl
dev.example.com {
    // Enable geoip_filter
    geoip_filter mode="whitelist" countries="VN SG" allow_unknown true db_path "/path/to/GeoLite2-Country.mmdb"

    // Enhanced logging for development
    log "/var/log/ferron/dev.access.log"
    error_log "/var/log/ferron/dev.error.log"

    // Custom test endpoints
    status 200 url="/test" body="Test endpoint working"
    status 500 url="/test-error" body="Simulated error"
}
```