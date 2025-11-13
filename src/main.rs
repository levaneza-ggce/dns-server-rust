use std::net::UdpSocket;
use std::io::Result;

// DNS Header structure
#[derive(Debug)]
struct DnsHeader {
    id: u16,
    flags: u16,
    question_count: u16,
    answer_count: u16,
    authority_count: u16,
    additional_count: u16,
}

impl DnsHeader {
    fn parse(buffer: &[u8]) -> Option<Self> {
        if buffer.len() < 12 {
            return None;
        }

        Some(DnsHeader {
            id: u16::from_be_bytes([buffer[0], buffer[1]]),
            flags: u16::from_be_bytes([buffer[2], buffer[3]]),
            question_count: u16::from_be_bytes([buffer[4], buffer[5]]),
            answer_count: u16::from_be_bytes([buffer[6], buffer[7]]),
            authority_count: u16::from_be_bytes([buffer[8], buffer[9]]),
            additional_count: u16::from_be_bytes([buffer[10], buffer[11]]),
        })
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.id.to_be_bytes());
        bytes.extend_from_slice(&self.flags.to_be_bytes());
        bytes.extend_from_slice(&self.question_count.to_be_bytes());
        bytes.extend_from_slice(&self.answer_count.to_be_bytes());
        bytes.extend_from_slice(&self.authority_count.to_be_bytes());
        bytes.extend_from_slice(&self.additional_count.to_be_bytes());
        bytes
    }
}

// DNS Question structure
#[derive(Debug)]
struct DnsQuestion {
    name: String,
    qtype: u16,
    qclass: u16,
}

// Parse domain name from DNS packet
fn parse_domain_name(buffer: &[u8], offset: &mut usize) -> Option<String> {
    let mut parts = Vec::new();
    let mut pos = *offset;

    loop {
        if pos >= buffer.len() {
            return None;
        }

        let length = buffer[pos] as usize;

        if length == 0 {
            pos += 1;
            break;
        }

        // Check for pointer (compression)
        if length & 0xC0 == 0xC0 {
            if pos + 1 >= buffer.len() {
                return None;
            }
            let pointer = ((buffer[pos] as usize & 0x3F) << 8) | buffer[pos + 1] as usize;
            let mut temp_offset = pointer;
            if let Some(name) = parse_domain_name(buffer, &mut temp_offset) {
                parts.push(name);
            }
            pos += 2;
            break;
        }

        pos += 1;
        if pos + length > buffer.len() {
            return None;
        }

        let label = String::from_utf8_lossy(&buffer[pos..pos + length]).to_string();
        parts.push(label);
        pos += length;
    }

    *offset = pos;
    Some(parts.join("."))
}

// Encode domain name to DNS format
fn encode_domain_name(name: &str) -> Vec<u8> {
    let mut bytes = Vec::new();

    for part in name.split('.') {
        if !part.is_empty() {
            bytes.push(part.len() as u8);
            bytes.extend_from_slice(part.as_bytes());
        }
    }

    bytes.push(0); // Null terminator
    bytes
}

// Parse DNS question section
fn parse_question(buffer: &[u8], offset: &mut usize) -> Option<DnsQuestion> {
    let name = parse_domain_name(buffer, offset)?;

    if *offset + 4 > buffer.len() {
        return None;
    }

    let qtype = u16::from_be_bytes([buffer[*offset], buffer[*offset + 1]]);
    let qclass = u16::from_be_bytes([buffer[*offset + 2], buffer[*offset + 3]]);
    *offset += 4;

    Some(DnsQuestion {
        name,
        qtype,
        qclass,
    })
}

// Create DNS response
fn create_response(query_buffer: &[u8], query_len: usize) -> Option<Vec<u8>> {
    let header = DnsHeader::parse(query_buffer)?;

    let mut offset = 12;
    let question = parse_question(query_buffer, &mut offset)?;

    println!("Received query for: {} (type: {})", question.name, question.qtype);

    // Create response header
    let response_header = DnsHeader {
        id: header.id,
        flags: 0x8180, // Standard query response, no error
        question_count: 1,
        answer_count: 1,
        authority_count: 0,
        additional_count: 0,
    };

    let mut response = response_header.to_bytes();

    // Add question section (echo back)
    let name_bytes = encode_domain_name(&question.name);
    response.extend_from_slice(&name_bytes);
    response.extend_from_slice(&question.qtype.to_be_bytes());
    response.extend_from_slice(&question.qclass.to_be_bytes());

    // Add answer section (A record pointing to 127.0.0.1)
    // Name (pointer to question)
    response.push(0xC0);
    response.push(0x0C);

    // Type (A record)
    response.extend_from_slice(&1u16.to_be_bytes());

    // Class (IN)
    response.extend_from_slice(&1u16.to_be_bytes());

    // TTL (300 seconds)
    response.extend_from_slice(&300u32.to_be_bytes());

    // Data length (4 bytes for IPv4)
    response.extend_from_slice(&4u16.to_be_bytes());

    // IP address (127.0.0.1 for demo)
    response.extend_from_slice(&[127, 0, 0, 1]);

    Some(response)
}

fn main() -> Result<()> {
    println!("Starting DNS Server on 0.0.0.0:5353");
    println!("Press Ctrl+C to stop");
    println!("---");

    let socket = UdpSocket::bind("0.0.0.0:5353")?;
    let mut buffer = [0u8; 512];

    println!("DNS Server is ready to receive queries");
    println!("Test with: dig @127.0.0.1 -p 5353 example.com");
    println!("---");

    loop {
        match socket.recv_from(&mut buffer) {
            Ok((size, source)) => {
                println!("\nReceived {} bytes from {}", size, source);

                if let Some(response) = create_response(&buffer, size) {
                    match socket.send_to(&response, source) {
                        Ok(_) => println!("Sent response to {}", source),
                        Err(e) => eprintln!("Failed to send response: {}", e),
                    }
                } else {
                    eprintln!("Failed to parse DNS query");
                }
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
            }
        }
    }
}
