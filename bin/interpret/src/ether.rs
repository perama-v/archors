//! For representing a ether value.

use alloy_primitives::U256;
use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EtherError {
    #[error("serde_json error {0}")]
    SerdeJson(#[from] serde_json::Error),
    #[error("Unable to get next char from string")]
    EndOfString,
}

/// Quantity in wei
///
/// As hex-value like 0x1 (1 wei)
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ether(pub String);

impl Display for Ether {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            to_ether_pretty(&self.0).map_err(|_| std::fmt::Error)?
        )
    }
}

/// Human relatable approximate amount.
///
/// E.g., ~1.2 ether, ~0.0020 ether (no rounding)
///
/// Input is hex-string (0x-prefix) in wei.
fn to_ether_pretty(hex_wei: &str) -> Result<String, EtherError> {
    let val = U256::from_str(hex_wei).unwrap();
    let num = val.to_string();
    let mut chars = num.chars();
    let decimals = val.approx_log10() as u64;
    let ether = match decimals {
        0_u64..=14_u64 => "<0.001".to_string(),
        15 => format!("0.00{}", next_char(&mut chars)?),
        16 => format!("0.0{}{}", next_char(&mut chars)?, next_char(&mut chars)?),
        17 => format!("0.{}{}", next_char(&mut chars)?, next_char(&mut chars)?),
        18 => format!("{}.{}", next_char(&mut chars)?, next_char(&mut chars)?),
        19 => format!(
            "{}{}.{}",
            next_char(&mut chars)?,
            next_char(&mut chars)?,
            next_char(&mut chars)?
        ),
        20 => format!(
            "{}{}{}.{}",
            next_char(&mut chars)?,
            next_char(&mut chars)?,
            next_char(&mut chars)?,
            next_char(&mut chars)?
        ),
        x @ 21_u64..=u64::MAX => format!("{val:.*}", x as usize),
    };
    Ok(ether)
}

/// Gets next char from a string.
fn next_char(chars: &mut std::str::Chars<'_>) -> Result<char, EtherError> {
    chars.next().ok_or(EtherError::EndOfString)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_to_approx_ether() {
        // 12648828125000 wei (0.000012)
        assert_eq!(to_ether_pretty("0xb8108e83f48").unwrap(), "<0.001");
        // 202381250000000 wei (0.00020)
        assert_eq!(to_ether_pretty("0xb8108e83f480").unwrap(), "<0.001");
        // 3238100000000000 wei (0.0032)
        assert_eq!(to_ether_pretty("0xb8108e83f4800").unwrap(), "0.003");
        // 6267810000000000 wei
        assert_eq!(to_ether_pretty("0x16448a3c91d400").unwrap(), "0.006");
        // 13234510000000000 wei
        assert_eq!(to_ether_pretty("0x2f04b77b538c00").unwrap(), "0.013");
        // 657311630000000000 wei
        assert_eq!(to_ether_pretty("0x91f3d71e4e20c00").unwrap(), "0.65");
        // 839991880000000000 wei
        assert_eq!(to_ether_pretty("0xba8402a159cd000").unwrap(), "0.83");
        // 1597427080000000000 wei
        assert_eq!(to_ether_pretty("0x162b337739fd5000").unwrap(), "1.5");
        // 1597427080000000000 wei
        assert_eq!(to_ether_pretty("0x162b337739fd5000").unwrap(), "1.5");
        // 25558833280000000000 wei
        assert_eq!(to_ether_pretty("0x162b337739fd50000").unwrap(), "25.5");
        // 408941332480000000000 wei
        assert_eq!(to_ether_pretty("0x162b337739fd500000").unwrap(), "408.9");
    }
}
