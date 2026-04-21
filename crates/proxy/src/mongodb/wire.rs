//! MongoDB OP_MSG wire protocol parsing.
//!
//! Handles the OP_MSG frame format (opCode 2013) introduced in MongoDB 3.6.
//! Legacy opcodes (OP_QUERY, OP_INSERT, etc.) are treated as `Unknown` and
//! forwarded without inspection.

use bson::Document;
use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

use uninc_common::error::UnincError;

/// MongoDB wire protocol opcode for OP_MSG.
pub const OP_MSG: i32 = 2013;

/// Standard header size for all MongoDB wire protocol messages.
pub const HEADER_SIZE: usize = 16;

/// Maximum allowed message size (48 MiB, matching MongoDB's default).
pub const MAX_MSG_SIZE: usize = 48 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The 16-byte header present on every MongoDB wire protocol message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsgHeader {
    pub message_length: i32,
    pub request_id: i32,
    pub response_to: i32,
    pub op_code: i32,
}

/// A parsed OP_MSG frame containing the BSON body document.
#[derive(Debug, Clone)]
pub struct OpMsg {
    pub header: MsgHeader,
    pub flag_bits: u32,
    pub body: Document,
}

/// A raw, unparsed message with an opcode other than OP_MSG.
#[derive(Debug, Clone)]
pub struct RawMessage {
    pub header: MsgHeader,
    pub payload: Vec<u8>,
}

/// Either a parsed OP_MSG or a raw unknown-opcode message.
#[derive(Debug)]
pub enum WireMessage {
    OpMsg(OpMsg),
    Unknown(RawMessage),
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a 16-byte MongoDB header from the given byte slice.
///
/// # Panics
///
/// Panics if `bytes.len() < 16`.
pub fn parse_header(bytes: &[u8]) -> MsgHeader {
    assert!(
        bytes.len() >= HEADER_SIZE,
        "need at least 16 bytes for MsgHeader"
    );
    let mut cursor = &bytes[..];
    MsgHeader {
        message_length: cursor.get_i32_le(),
        request_id: cursor.get_i32_le(),
        response_to: cursor.get_i32_le(),
        op_code: cursor.get_i32_le(),
    }
}

/// Parse an OP_MSG frame from a complete message buffer.
///
/// The buffer must include the full message (header + body) and the header's
/// `opCode` must be `OP_MSG` (2013).
pub fn parse_op_msg(bytes: &[u8]) -> Result<OpMsg, UnincError> {
    if bytes.len() < HEADER_SIZE + 4 {
        return Err(UnincError::ProtocolParse(
            "message too short for OP_MSG".into(),
        ));
    }

    let header = parse_header(bytes);

    if header.op_code != OP_MSG {
        return Err(UnincError::ProtocolParse(format!(
            "expected OP_MSG (2013), got opCode {}",
            header.op_code
        )));
    }

    let mut cursor = &bytes[HEADER_SIZE..];

    // flagBits (4 bytes, little-endian)
    let flag_bits = cursor.get_u32_le();

    // Section kind 0 (body): the first byte should be 0x00 for a body section.
    // Per the spec, kind byte is present only when there are multiple sections,
    // but in practice drivers always include it. We handle both cases:
    // peek at the first byte — if it looks like a section kind byte (0), consume it.
    if !cursor.is_empty() && cursor[0] == 0 {
        cursor.advance(1); // skip section kind byte
    }

    // The remainder is a BSON document (Section 0 body).
    let body = bson::from_slice(cursor).map_err(|e| {
        UnincError::ProtocolParse(format!("failed to deserialize BSON body: {e}"))
    })?;

    Ok(OpMsg {
        header,
        flag_bits,
        body,
    })
}

/// Read one complete MongoDB wire protocol message from an async stream.
///
/// Returns `WireMessage::OpMsg` for opCode 2013, or `WireMessage::Unknown`
/// for legacy opcodes.
pub async fn read_wire_message<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<WireMessage, UnincError> {
    // Read the first 4 bytes to get message_length.
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf).await.map_err(|e| {
        UnincError::ProtocolParse(format!("failed to read message length: {e}"))
    })?;
    let message_length = i32::from_le_bytes(len_buf);

    if message_length < HEADER_SIZE as i32 {
        return Err(UnincError::ProtocolParse(format!(
            "invalid message length: {message_length}"
        )));
    }
    if message_length as usize > MAX_MSG_SIZE {
        return Err(UnincError::ProtocolParse(format!(
            "message too large: {message_length} bytes (max {MAX_MSG_SIZE})"
        )));
    }

    // Read the rest of the message.
    let total_len = message_length as usize;
    let mut buf = BytesMut::with_capacity(total_len);
    buf.extend_from_slice(&len_buf);
    buf.resize(total_len, 0);
    reader.read_exact(&mut buf[4..]).await.map_err(|e| {
        UnincError::ProtocolParse(format!("failed to read message body: {e}"))
    })?;

    let header = parse_header(&buf);

    if header.op_code == OP_MSG {
        let op_msg = parse_op_msg(&buf)?;
        Ok(WireMessage::OpMsg(op_msg))
    } else {
        Ok(WireMessage::Unknown(RawMessage {
            header,
            payload: buf.to_vec(),
        }))
    }
}

/// Convenience wrapper: read from a stream and return only if it is an OP_MSG.
pub async fn read_op_msg<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<OpMsg, UnincError> {
    match read_wire_message(reader).await? {
        WireMessage::OpMsg(msg) => Ok(msg),
        WireMessage::Unknown(raw) => Err(UnincError::ProtocolParse(format!(
            "expected OP_MSG, got opCode {}",
            raw.header.op_code
        ))),
    }
}

/// Serialize an OP_MSG header + flagBits + BSON body into a byte vector.
///
/// Useful for constructing test fixtures and forwarding rewritten messages.
pub fn serialize_op_msg(request_id: i32, response_to: i32, flag_bits: u32, body: &Document) -> Vec<u8> {
    let mut bson_bytes = Vec::new();
    body.to_writer(&mut bson_bytes).expect("BSON serialization");

    // total = header(16) + flagBits(4) + kind_byte(1) + bson_bytes
    let total_len = HEADER_SIZE + 4 + 1 + bson_bytes.len();
    let mut buf = Vec::with_capacity(total_len);

    buf.extend_from_slice(&(total_len as i32).to_le_bytes());
    buf.extend_from_slice(&request_id.to_le_bytes());
    buf.extend_from_slice(&response_to.to_le_bytes());
    buf.extend_from_slice(&OP_MSG.to_le_bytes());
    buf.extend_from_slice(&flag_bits.to_le_bytes());
    buf.push(0); // section kind 0 = body
    buf.extend_from_slice(&bson_bytes);

    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use bson::doc;

    fn make_op_msg_bytes(body: &Document) -> Vec<u8> {
        serialize_op_msg(1, 0, 0, body)
    }

    #[test]
    fn parse_header_roundtrip() {
        let header = MsgHeader {
            message_length: 100,
            request_id: 42,
            response_to: 0,
            op_code: OP_MSG,
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(&header.message_length.to_le_bytes());
        buf.extend_from_slice(&header.request_id.to_le_bytes());
        buf.extend_from_slice(&header.response_to.to_le_bytes());
        buf.extend_from_slice(&header.op_code.to_le_bytes());

        let parsed = parse_header(&buf);
        assert_eq!(parsed, header);
    }

    #[test]
    fn parse_op_msg_find_command() {
        let body = doc! { "find": "users", "filter": { "age": 25 } };
        let buf = make_op_msg_bytes(&body);
        let msg = parse_op_msg(&buf).unwrap();

        assert_eq!(msg.header.op_code, OP_MSG);
        assert_eq!(msg.flag_bits, 0);
        assert_eq!(msg.body.get_str("find").unwrap(), "users");
    }

    #[test]
    fn parse_op_msg_wrong_opcode_errors() {
        let body = doc! { "ping": 1 };
        let mut buf = make_op_msg_bytes(&body);
        // Overwrite opcode to a legacy value (OP_QUERY = 2004)
        buf[12..16].copy_from_slice(&2004_i32.to_le_bytes());
        let result = parse_op_msg(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn parse_op_msg_insert_command() {
        let body = doc! {
            "insert": "orders",
            "documents": [{ "item": "widget", "qty": 10 }]
        };
        let buf = make_op_msg_bytes(&body);
        let msg = parse_op_msg(&buf).unwrap();
        assert_eq!(msg.body.get_str("insert").unwrap(), "orders");
    }

    #[tokio::test]
    async fn read_op_msg_from_stream() {
        let body = doc! { "find": "products", "$db": "shop" };
        let buf = make_op_msg_bytes(&body);

        let mut cursor = std::io::Cursor::new(buf);
        let msg = read_op_msg(&mut cursor).await.unwrap();
        assert_eq!(msg.body.get_str("find").unwrap(), "products");
    }

    #[tokio::test]
    async fn read_wire_message_unknown_opcode() {
        let body = doc! { "query": "test" };
        let mut buf = make_op_msg_bytes(&body);
        // Overwrite opcode to OP_QUERY (2004)
        buf[12..16].copy_from_slice(&2004_i32.to_le_bytes());

        let mut cursor = std::io::Cursor::new(buf);
        let msg = read_wire_message(&mut cursor).await.unwrap();
        assert!(matches!(msg, WireMessage::Unknown(_)));
    }

    #[test]
    fn serialize_and_parse_roundtrip() {
        let body = doc! {
            "aggregate": "events",
            "pipeline": [{ "$match": { "type": "click" } }],
            "cursor": {}
        };
        let buf = serialize_op_msg(7, 0, 0, &body);
        let msg = parse_op_msg(&buf).unwrap();
        assert_eq!(msg.header.request_id, 7);
        assert_eq!(msg.body.get_str("aggregate").unwrap(), "events");
    }
}
