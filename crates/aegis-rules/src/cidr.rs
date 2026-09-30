//! IP-CIDR（v4 / v6 统一，PRD F2）。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ParseError;

/// 一个 CIDR 块。构建时把网络地址掩码化（`10.1.2.3/8` 归一为 `10.0.0.0/8`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl IpCidr {
    pub fn new(network: IpAddr, prefix: u8) -> Result<Self, ParseError> {
        let max = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return Err(ParseError::BadCidr(format!("{network}/{prefix}")));
        }
        Ok(Self {
            network: masked(network, prefix),
            prefix,
        })
    }

    /// 解析 `10.0.0.0/8`、`2001:db8::/32`；无前缀长度的单 IP 视为 `/32` 或 `/128`。
    pub fn parse(s: &str) -> Result<Self, ParseError> {
        let (ip, prefix) = match s.split_once('/') {
            Some((ip, p)) => (
                parse_ip(ip)?,
                p.parse::<u8>().map_err(|_| ParseError::BadCidr(s.into()))?,
            ),
            None => (parse_ip(s)?, 0), // 占位，下方按地址族补全
        };
        let prefix = if s.contains('/') {
            prefix
        } else {
            full_prefix(&ip)
        };
        Self::new(ip, prefix)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.network, ip) {
            (IpAddr::V4(n), IpAddr::V4(i)) => {
                masked_v4(u32::from(n), self.prefix) == masked_v4(u32::from(i), self.prefix)
            }
            (IpAddr::V6(n), IpAddr::V6(i)) => {
                masked_v6(u128::from(n), self.prefix) == masked_v6(u128::from(i), self.prefix)
            }
            // 跨地址族（v4 块 vs v6 地址）永不匹配
            _ => false,
        }
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }
}

fn parse_ip(s: &str) -> Result<IpAddr, ParseError> {
    s.parse().map_err(|_| ParseError::BadCidr(s.into()))
}

fn full_prefix(ip: &IpAddr) -> u8 {
    match ip {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    }
}

fn masked(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v) => IpAddr::V4(Ipv4Addr::from(masked_v4(u32::from(v), prefix))),
        IpAddr::V6(v) => IpAddr::V6(Ipv6Addr::from(masked_v6(u128::from(v), prefix))),
    }
}

fn masked_v4(bits: u32, prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        (bits >> (32 - prefix)) << (32 - prefix)
    }
}

fn masked_v6(bits: u128, prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        (bits >> (128 - prefix)) << (128 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_match() {
        let cidr = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(cidr.contains("10.255.0.1".parse().unwrap()));
        assert!(!cidr.contains("11.0.0.1".parse().unwrap()));
        assert_eq!(cidr.prefix(), 8);
    }

    #[test]
    fn v6_match() {
        let cidr = IpCidr::parse("2001:db8::/32").unwrap();
        assert!(cidr.contains("2001:db8::1".parse().unwrap()));
        assert!(!cidr.contains("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn family_mismatch_and_normalization() {
        let cidr = IpCidr::new("10.1.2.3".parse().unwrap(), 8).unwrap();
        // 10.1.2.3/8 与 10.0.0.0/8 等价
        assert_eq!(cidr, IpCidr::parse("10.0.0.0/8").unwrap());
        // v4 块不匹配 v6 地址（::ffff: 映射地址也不算，避免静默穿越）
        assert!(!cidr.contains("::ffff:10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn single_ip_is_full_prefix() {
        assert_eq!(IpCidr::parse("1.2.3.4").unwrap().prefix(), 32);
        assert!(IpCidr::parse("2001:db8::1").unwrap().prefix() == 128);
    }

    #[test]
    fn bad_input() {
        assert!(IpCidr::parse("10.0.0.0/33").is_err());
        assert!(IpCidr::parse("10.0.0.0/abc").is_err());
        assert!(IpCidr::parse("not-an-ip").is_err());
    }
}
