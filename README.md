# DNS Server in Rust

A simple DNS server implementation written in Rust that can parse DNS queries and respond with DNS answers.

## Features

- DNS query parsing with support for domain name compression
- UDP-based DNS server running on port 5353
- DNS response generation with A records
- Clean, safe Rust implementation

## Building

```bash
cargo build --release
```

## Running

```bash
cargo run --release
```

The DNS server will start on `0.0.0.0:5353`.

## Testing

You can test the DNS server using `dig`:

```bash
dig @127.0.0.1 -p 5353 example.com
```

## Implementation Details

This DNS server includes:
- DNS header parsing and serialization
- Domain name encoding/decoding with compression support
- DNS question section parsing
- DNS answer generation (returns 127.0.0.1 for all A record queries)

## License

MIT
