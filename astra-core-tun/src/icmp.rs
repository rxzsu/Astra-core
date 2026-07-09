/// ICMP utilities for TUN.
/// Mirrors Go's `proxy/tun/stack_gvisor_icmp_handler.go` and `proxy/tun/icmp/`.

/// Parse an ICMP echo request from a raw IP packet.
/// Returns (identifier, sequence_number, success).
pub fn parse_echo_request(data: &[u8], is_ipv6: bool) -> Option<(u16, u16)> {
    let ip_header_len = if is_ipv6 { 40 } else { 20 };
    if data.len() < ip_header_len + 8 {
        return None;
    }

    let icmp_type = data[ip_header_len];
    let icmp_code = data[ip_header_len + 1];

    // ICMPv4 Echo Request = type 8, code 0
    // ICMPv6 Echo Request = type 128, code 0
    let is_echo_request = if is_ipv6 {
        icmp_type == 128 && icmp_code == 0
    } else {
        icmp_type == 8 && icmp_code == 0
    };

    if !is_echo_request {
        return None;
    }

    let ident = u16::from_be_bytes([data[ip_header_len + 4], data[ip_header_len + 5]]);
    let seq = u16::from_be_bytes([data[ip_header_len + 6], data[ip_header_len + 7]]);

    Some((ident, seq))
}

/// Build an ICMP echo reply from a request.
pub fn build_echo_reply(data: &[u8], is_ipv6: bool) -> Option<Vec<u8>> {
    let ip_header_len = if is_ipv6 { 40 } else { 20 };
    if data.len() < ip_header_len + 8 {
        return None;
    }

    let mut reply = Vec::with_capacity(data.len());

    // Copy IP header
    reply.extend_from_slice(&data[..ip_header_len]);

    // Swap source and destination IP addresses
    if is_ipv6 {
        // IPv6: src=8..24, dst=24..40
        reply[8..24].copy_from_slice(&data[24..40]);
        reply[24..40].copy_from_slice(&data[8..24]);
    } else {
        // IPv4: src=12..16, dst=16..20
        reply[12..16].copy_from_slice(&data[16..20]);
        reply[16..20].copy_from_slice(&data[12..16]);
        // Reset IP checksum (will recalculate)
        reply[10] = 0;
        reply[11] = 0;
    }

    // Build ICMP part
    if is_ipv6 {
        reply.push(129); // ICMPv6 Echo Reply
    } else {
        reply.push(0); // ICMPv4 Echo Reply
    }
    reply.push(0); // Code = 0
    reply.push(0); // Checksum high (placeholder)
    reply.push(0); // Checksum low (placeholder)
    // Copy rest from original (identifier, sequence, data)
    reply.extend_from_slice(&data[ip_header_len + 4..]);

    // Calculate ICMP checksum
    let icmp_start = ip_header_len;
    let icmp_len = reply.len() - icmp_start;
    let checksum = compute_checksum(&reply[icmp_start..], icmp_len);
    reply[ip_header_len + 2] = (checksum >> 8) as u8;
    reply[ip_header_len + 3] = (checksum & 0xFF) as u8;

    // Calculate IP checksum for IPv4
    if !is_ipv6 {
        let ip_checksum = compute_checksum(&reply[..20], 20);
        reply[10] = (ip_checksum >> 8) as u8;
        reply[11] = (ip_checksum & 0xFF) as u8;
    }

    Some(reply)
}

/// Compute the Internet checksum (RFC 1071).
pub fn compute_checksum(data: &[u8], len: usize) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < len {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < len {
        sum += u32::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    (!sum) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checksum() {
        let data = [0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00, 0x40, 0x01];
        let _cksum = compute_checksum(&data, data.len());
        // Just verify it runs without panicking
        assert!(_cksum > 0);
    }

    #[test]
    fn test_parse_echo_request() {
        // Minimal IPv4 + ICMP echo request
        let mut pkt = vec![0u8; 28];
        // IPv4 header
        pkt[0] = 0x45; // Version 4, IHL 5
        pkt[1] = 0x00;
        pkt[2] = 0x00;
        pkt[3] = 0x1C; // Total length
        pkt[8] = 0x40; // TTL
        pkt[9] = 0x01; // Protocol = ICMP
        // Source IP: 10.0.0.1
        pkt[12] = 10;
        pkt[13] = 0;
        pkt[14] = 0;
        pkt[15] = 1;
        // Dest IP: 10.0.0.2
        pkt[16] = 10;
        pkt[17] = 0;
        pkt[18] = 0;
        pkt[19] = 2;
        // ICMP: Echo Request
        pkt[20] = 8; // Type
        pkt[21] = 0; // Code
        pkt[24] = 0x12;
        pkt[25] = 0x34; // Identifier
        pkt[26] = 0x56;
        pkt[27] = 0x78; // Sequence

        let result = parse_echo_request(&pkt, false);
        assert!(result.is_some());
        let (ident, seq) = result.unwrap();
        assert_eq!(ident, 0x1234);
        assert_eq!(seq, 0x5678);

        let reply = build_echo_reply(&pkt, false);
        assert!(reply.is_some());
        let reply = reply.unwrap();
        assert_eq!(reply[20], 0); // Type = Echo Reply
        // Check IP swap
        assert_eq!(reply[12..16], [10, 0, 0, 2]); // src became dest
        assert_eq!(reply[16..20], [10, 0, 0, 1]); // dest became src
    }
}
