//! Cells, the units Tor sends over links, and the relay messages that
//! travel inside relay cells along a circuit.

/// Bytes in the payload of a fixed-length cell.
pub const PAYLOAD_LEN: usize = 509;
/// Bytes of data one relay cell carries.
pub const RELAY_DATA_LEN: usize = PAYLOAD_LEN - 11;

pub const PADDING: u8 = 0;
pub const CREATE: u8 = 1;
pub const CREATED: u8 = 2;
pub const RELAY: u8 = 3;
pub const DESTROY: u8 = 4;
pub const CREATE_FAST: u8 = 5;
pub const CREATED_FAST: u8 = 6;
pub const VERSIONS: u8 = 7;
pub const NETINFO: u8 = 8;
pub const RELAY_EARLY: u8 = 9;
pub const CREATE2: u8 = 10;
pub const CREATED2: u8 = 11;
pub const VPADDING: u8 = 128;
pub const CERTS: u8 = 129;
pub const AUTH_CHALLENGE: u8 = 130;

pub const BEGIN: u8 = 1;
pub const DATA: u8 = 2;
pub const END: u8 = 3;
pub const CONNECTED: u8 = 4;
pub const SENDME: u8 = 5;
pub const TRUNCATED: u8 = 9;
pub const DROP: u8 = 10;
pub const BEGIN_DIR: u8 = 13;
pub const EXTEND2: u8 = 14;
pub const EXTENDED2: u8 = 15;
pub const ESTABLISH_RENDEZVOUS: u8 = 33;
pub const INTRODUCE1: u8 = 34;
pub const RENDEZVOUS2: u8 = 37;
pub const RENDEZVOUS_ESTABLISHED: u8 = 39;
pub const INTRODUCE_ACK: u8 = 40;

/// VERSIONS and commands from 128 on have a length field.
pub const fn is_variable(command: u8) -> bool {
    command == VERSIONS || command >= 128
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    pub circuit: u32,
    pub command: u8,
    pub payload: Vec<u8>,
}

impl Cell {
    pub fn new(circuit: u32, command: u8, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            circuit,
            command,
            payload: payload.into(),
        }
    }

    /// The cell with a circuit id of `id_len` bytes: 2 before the link
    /// version is agreed, 4 after. Fixed cells are padded with zeros.
    pub fn encode_with(&self, id_len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(id_len + 3 + PAYLOAD_LEN);
        out.extend_from_slice(&self.circuit.to_be_bytes()[4 - id_len..]);
        out.push(self.command);
        if is_variable(self.command) {
            out.extend_from_slice(&(self.payload.len() as u16).to_be_bytes());
            out.extend_from_slice(&self.payload);
        } else {
            let length = self.payload.len().min(PAYLOAD_LEN);
            out.extend_from_slice(&self.payload[..length]);
            out.resize(id_len + 1 + PAYLOAD_LEN, 0);
        }
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        self.encode_with(4)
    }

    /// Reads the cell at the start of `bytes`. Returns it with its length,
    /// or None if more bytes are needed.
    pub fn decode_with(bytes: &[u8], id_len: usize) -> Option<(Self, usize)> {
        let command = *bytes.get(id_len)?;
        let mut id = [0u8; 4];
        id[4 - id_len..].copy_from_slice(&bytes[..id_len]);
        let (start, length) = if is_variable(command) {
            let length = bytes.get(id_len + 1..id_len + 3)?;
            (
                id_len + 3,
                usize::from(u16::from_be_bytes([length[0], length[1]])),
            )
        } else {
            (id_len + 1, PAYLOAD_LEN)
        };
        let payload = bytes.get(start..start + length)?;
        Some((
            Self::new(u32::from_be_bytes(id), command, payload),
            start + length,
        ))
    }

    pub fn decode(bytes: &[u8]) -> Option<Self> {
        Self::decode_with(bytes, 4).map(|(cell, _)| cell)
    }
}

/// A relay message: the plaintext of a relay cell at the hop that sends or
/// reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayMessage {
    pub command: u8,
    pub stream: u16,
    pub data: Vec<u8>,
}

impl RelayMessage {
    pub fn new(command: u8, stream: u16, data: impl Into<Vec<u8>>) -> Self {
        Self {
            command,
            stream,
            data: data.into(),
        }
    }

    /// The relay payload with the recognized and digest fields zero. After
    /// the data come four zero bytes and random padding, which keeps cell
    /// contents unpredictable.
    pub fn encode(&self) -> [u8; PAYLOAD_LEN] {
        let length = self.data.len().min(RELAY_DATA_LEN);
        let mut out = [0u8; PAYLOAD_LEN];
        out[0] = self.command;
        out[3..5].copy_from_slice(&self.stream.to_be_bytes());
        out[9..11].copy_from_slice(&(length as u16).to_be_bytes());
        out[11..11 + length].copy_from_slice(&self.data[..length]);
        let padding_start = 11 + length + 4;
        if padding_start < PAYLOAD_LEN {
            getrandom::getrandom(&mut out[padding_start..]).expect("system random source");
        }
        out
    }

    pub fn decode(payload: &[u8; PAYLOAD_LEN]) -> Option<Self> {
        let length = usize::from(u16::from_be_bytes([payload[9], payload[10]]));
        let data = payload.get(11..11 + length)?;
        if length > RELAY_DATA_LEN {
            return None;
        }
        Some(Self::new(
            payload[0],
            u16::from_be_bytes([payload[3], payload[4]]),
            data,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_and_variable_cells_round_trip() {
        let fixed = Cell::new(0x8000_0001, CREATE2, vec![1, 2, 3]);
        let bytes = fixed.encode();
        assert_eq!(bytes.len(), 4 + 1 + PAYLOAD_LEN);
        let (decoded, length) = Cell::decode_with(&bytes, 4).unwrap();
        assert_eq!(length, bytes.len());
        assert_eq!(decoded.payload[..3], [1, 2, 3]);
        let versions = Cell::new(0, VERSIONS, vec![0, 4, 0, 5]);
        let bytes = versions.encode_with(2);
        assert_eq!(bytes, [0, 0, VERSIONS, 0, 4, 0, 4, 0, 5]);
        assert_eq!(Cell::decode_with(&bytes, 2).unwrap().0, versions);
        assert!(Cell::decode_with(&bytes[..6], 2).is_none());
    }

    #[test]
    fn relay_messages_round_trip_with_random_padding() {
        let message = RelayMessage::new(DATA, 7, b"hello".to_vec());
        let payload = message.encode();
        assert_eq!(payload[1..3], [0, 0]);
        assert_eq!(payload[5..9], [0, 0, 0, 0]);
        assert_eq!(payload[16..20], [0, 0, 0, 0]);
        assert_eq!(RelayMessage::decode(&payload), Some(message));
    }
}
