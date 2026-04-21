//! Postgres wire protocol message parsing.
//!
//! Implements reading and writing of the Postgres v3 wire protocol messages
//! for both frontend (client -> server) and backend (server -> client) directions.
//!
//! Wire format:
//! - StartupMessage: `length(i32) || protocol_version(i32=196608) || key=value\0 pairs || \0`
//! - All other frontend messages: `tag(u8) || length(i32, includes self) || payload`
//! - All backend messages: `tag(u8) || length(i32, includes self) || payload`

use std::collections::HashMap;

use bytes::{Buf, BufMut, BytesMut};

// ---------------------------------------------------------------------------
// Frontend messages (client -> server)
// ---------------------------------------------------------------------------

/// A message sent from a Postgres client to the server.
#[derive(Debug, Clone, PartialEq)]
pub enum FrontendMessage {
    StartupMessage {
        user: String,
        database: String,
        params: HashMap<String, String>,
    },
    Query {
        sql: String,
    },
    Parse {
        name: String,
        sql: String,
        param_types: Vec<i32>,
    },
    Bind {
        portal: String,
        statement: String,
        params: Vec<Option<Vec<u8>>>,
    },
    Execute {
        portal: String,
        max_rows: i32,
    },
    Terminate,
    PasswordMessage(Vec<u8>),
    SASLInitialResponse {
        mechanism: String,
        data: Vec<u8>,
    },
    SASLResponse(Vec<u8>),
    Unknown {
        tag: u8,
        payload: Vec<u8>,
    },
}

// ---------------------------------------------------------------------------
// Backend messages (server -> client)
// ---------------------------------------------------------------------------

/// A message sent from the Postgres server to the client.
#[derive(Debug, Clone, PartialEq)]
pub enum BackendMessage {
    AuthenticationOk,
    AuthenticationCleartextPassword,
    AuthenticationMD5Password { salt: [u8; 4] },
    AuthenticationSASL { mechanisms: Vec<String> },
    AuthenticationSASLContinue(Vec<u8>),
    AuthenticationSASLFinal(Vec<u8>),
    ReadyForQuery { status: u8 },
    RowDescription { fields: Vec<FieldDescription> },
    DataRow { values: Vec<Option<Vec<u8>>> },
    CommandComplete { tag: String },
    ErrorResponse { fields: HashMap<u8, String> },
    ParseComplete,
    BindComplete,
    ParameterStatus { name: String, value: String },
    BackendKeyData { pid: i32, secret: i32 },
    Unknown { tag: u8, payload: Vec<u8> },
}

/// Description of a single field in a RowDescription message.
#[derive(Debug, Clone, PartialEq)]
pub struct FieldDescription {
    pub name: String,
    pub table_oid: i32,
    pub column_id: i16,
    pub type_oid: i32,
    pub type_size: i16,
    pub type_modifier: i32,
    pub format: i16,
}

// ---------------------------------------------------------------------------
// SSL negotiation
// ---------------------------------------------------------------------------

/// The SSL request message has a specific format:
/// length(i32=8) || code(i32=80877103)
pub const SSL_REQUEST_CODE: i32 = 80877103;

/// Postgres v3 protocol version: 3.0 = 196608
pub const PROTOCOL_VERSION_3: i32 = 196608;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during wire protocol parsing.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    #[error("insufficient data: need {needed} bytes, have {available}")]
    InsufficientData { needed: usize, available: usize },
    #[error("invalid message length: {0}")]
    InvalidLength(i32),
    #[error("invalid utf-8 in message: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
    #[error("unexpected end of null-terminated string")]
    UnterminatedString,
    #[error("unknown protocol version: {0}")]
    UnknownProtocolVersion(i32),
}

// ---------------------------------------------------------------------------
// Reading helpers
// ---------------------------------------------------------------------------

/// Read a null-terminated string from a byte slice, returning the string
/// and the number of bytes consumed (including the null terminator).
fn read_cstring(buf: &[u8]) -> Result<(String, usize), WireError> {
    match buf.iter().position(|&b| b == 0) {
        Some(pos) => {
            let s = String::from_utf8(buf[..pos].to_vec())?;
            Ok((s, pos + 1))
        }
        None => Err(WireError::UnterminatedString),
    }
}

/// Check whether we have a complete message in the buffer starting at the given offset.
/// Returns `Some(total_len)` if a complete message is available, `None` otherwise.
///
/// For startup messages (no tag byte), pass `is_startup = true`.
pub fn frame_length(buf: &[u8], is_startup: bool) -> Option<usize> {
    if is_startup {
        // Startup: first 4 bytes are length (includes self)
        if buf.len() < 4 {
            return None;
        }
        let len = i32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
        if buf.len() >= len {
            Some(len)
        } else {
            None
        }
    } else {
        // Tagged: tag(1) + length(4) + payload
        if buf.len() < 5 {
            return None;
        }
        let len = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        let total = 1 + len; // tag byte + (length field value which includes itself)
        if buf.len() >= total {
            Some(total)
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Startup / SSL request parsing
// ---------------------------------------------------------------------------

/// Result of reading the initial bytes from a new client connection.
/// Could be an SSL request, a startup message, or a cancel request.
#[derive(Debug)]
pub enum InitialMessage {
    SslRequest,
    Startup(FrontendMessage),
    CancelRequest { pid: i32, secret: i32 },
}

/// Parse the initial message from a client. This is the first message on a
/// new connection before any tag-based protocol is established.
///
/// Format: `length(i32) || code_or_version(i32) || ...`
pub fn parse_initial_message(buf: &[u8]) -> Result<InitialMessage, WireError> {
    if buf.len() < 8 {
        return Err(WireError::InsufficientData {
            needed: 8,
            available: buf.len(),
        });
    }

    let mut cursor = buf;
    let length = cursor.get_i32() as usize;
    let code = cursor.get_i32();

    if code == SSL_REQUEST_CODE {
        return Ok(InitialMessage::SslRequest);
    }

    // Cancel request: code = 80877102
    if code == 80877102 {
        if buf.len() < 16 {
            return Err(WireError::InsufficientData {
                needed: 16,
                available: buf.len(),
            });
        }
        let pid = cursor.get_i32();
        let secret = cursor.get_i32();
        return Ok(InitialMessage::CancelRequest { pid, secret });
    }

    if code != PROTOCOL_VERSION_3 {
        return Err(WireError::UnknownProtocolVersion(code));
    }

    // Parse key=value\0 pairs from the remainder of the startup message
    let payload = &buf[8..length];
    let mut params = HashMap::new();
    let mut offset = 0;

    while offset < payload.len() {
        if payload[offset] == 0 {
            break; // Final null terminator
        }
        let (key, consumed) = read_cstring(&payload[offset..])?;
        offset += consumed;
        if offset >= payload.len() {
            break;
        }
        let (value, consumed) = read_cstring(&payload[offset..])?;
        offset += consumed;
        params.insert(key, value);
    }

    let user = params.remove("user").unwrap_or_default();
    let database = params
        .remove("database")
        .unwrap_or_else(|| user.clone());

    Ok(InitialMessage::Startup(FrontendMessage::StartupMessage {
        user,
        database,
        params,
    }))
}

// ---------------------------------------------------------------------------
// Frontend message parsing (tagged messages after startup)
// ---------------------------------------------------------------------------

/// Parse a tagged frontend message from a complete message buffer.
/// The buffer must contain exactly one complete message: `tag(1) || length(4) || payload`.
pub fn parse_frontend_message(buf: &[u8]) -> Result<FrontendMessage, WireError> {
    if buf.len() < 5 {
        return Err(WireError::InsufficientData {
            needed: 5,
            available: buf.len(),
        });
    }

    let tag = buf[0];
    let length = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);

    if length < 4 {
        return Err(WireError::InvalidLength(length));
    }

    let payload = &buf[5..];

    match tag {
        // 'Q' — Simple Query
        b'Q' => {
            let (sql, _) = read_cstring(payload)?;
            Ok(FrontendMessage::Query { sql })
        }

        // 'P' — Parse (extended query protocol)
        b'P' => {
            let mut offset = 0;
            let (name, consumed) = read_cstring(&payload[offset..])?;
            offset += consumed;
            let (sql, consumed) = read_cstring(&payload[offset..])?;
            offset += consumed;

            let mut param_types = Vec::new();
            if offset + 2 <= payload.len() {
                let num_params =
                    i16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
                offset += 2;
                for _ in 0..num_params {
                    if offset + 4 <= payload.len() {
                        let oid = i32::from_be_bytes([
                            payload[offset],
                            payload[offset + 1],
                            payload[offset + 2],
                            payload[offset + 3],
                        ]);
                        param_types.push(oid);
                        offset += 4;
                    }
                }
            }

            Ok(FrontendMessage::Parse {
                name,
                sql,
                param_types,
            })
        }

        // 'B' — Bind
        b'B' => {
            let mut offset = 0;
            let (portal, consumed) = read_cstring(&payload[offset..])?;
            offset += consumed;
            let (statement, consumed) = read_cstring(&payload[offset..])?;
            offset += consumed;

            // Skip format codes
            if offset + 2 <= payload.len() {
                let num_format_codes =
                    i16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
                offset += 2;
                offset += num_format_codes * 2; // Each format code is 2 bytes
            }

            // Parameter values
            let mut params = Vec::new();
            if offset + 2 <= payload.len() {
                let num_params =
                    i16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
                offset += 2;
                for _ in 0..num_params {
                    if offset + 4 > payload.len() {
                        break;
                    }
                    let param_len = i32::from_be_bytes([
                        payload[offset],
                        payload[offset + 1],
                        payload[offset + 2],
                        payload[offset + 3],
                    ]);
                    offset += 4;
                    if param_len == -1 {
                        params.push(None); // NULL
                    } else {
                        let len = param_len as usize;
                        if offset + len <= payload.len() {
                            params.push(Some(payload[offset..offset + len].to_vec()));
                            offset += len;
                        }
                    }
                }
            }

            Ok(FrontendMessage::Bind {
                portal,
                statement,
                params,
            })
        }

        // 'E' — Execute
        b'E' => {
            let (portal, consumed) = read_cstring(payload)?;
            let rest = &payload[consumed..];
            let max_rows = if rest.len() >= 4 {
                i32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]])
            } else {
                0
            };
            Ok(FrontendMessage::Execute { portal, max_rows })
        }

        // 'X' — Terminate
        b'X' => Ok(FrontendMessage::Terminate),

        // 'p' — Password message (also used for SASL responses)
        b'p' => {
            // We need context to distinguish PasswordMessage from SASLResponse.
            // At the wire level they use the same tag. We'll return as PasswordMessage
            // by default; the connection state machine can reinterpret.
            Ok(FrontendMessage::PasswordMessage(payload.to_vec()))
        }

        _ => Ok(FrontendMessage::Unknown {
            tag,
            payload: payload.to_vec(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Backend message parsing
// ---------------------------------------------------------------------------

/// Parse a tagged backend message from a complete message buffer.
/// The buffer must contain exactly one complete message: `tag(1) || length(4) || payload`.
pub fn parse_backend_message(buf: &[u8]) -> Result<BackendMessage, WireError> {
    if buf.len() < 5 {
        return Err(WireError::InsufficientData {
            needed: 5,
            available: buf.len(),
        });
    }

    let tag = buf[0];
    let length = i32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);

    if length < 4 {
        return Err(WireError::InvalidLength(length));
    }

    let payload = &buf[5..];

    match tag {
        // 'R' — Authentication
        b'R' => parse_auth_message(payload),

        // 'Z' — ReadyForQuery
        b'Z' => {
            let status = if payload.is_empty() { b'I' } else { payload[0] };
            Ok(BackendMessage::ReadyForQuery { status })
        }

        // 'T' — RowDescription
        b'T' => {
            if payload.len() < 2 {
                return Ok(BackendMessage::Unknown {
                    tag,
                    payload: payload.to_vec(),
                });
            }
            let num_fields = i16::from_be_bytes([payload[0], payload[1]]) as usize;
            let mut offset = 2;
            let mut fields = Vec::with_capacity(num_fields);

            for _ in 0..num_fields {
                let (name, consumed) = read_cstring(&payload[offset..])?;
                offset += consumed;

                if offset + 18 > payload.len() {
                    break;
                }

                let table_oid = i32::from_be_bytes([
                    payload[offset],
                    payload[offset + 1],
                    payload[offset + 2],
                    payload[offset + 3],
                ]);
                offset += 4;

                let column_id =
                    i16::from_be_bytes([payload[offset], payload[offset + 1]]);
                offset += 2;

                let type_oid = i32::from_be_bytes([
                    payload[offset],
                    payload[offset + 1],
                    payload[offset + 2],
                    payload[offset + 3],
                ]);
                offset += 4;

                let type_size =
                    i16::from_be_bytes([payload[offset], payload[offset + 1]]);
                offset += 2;

                let type_modifier = i32::from_be_bytes([
                    payload[offset],
                    payload[offset + 1],
                    payload[offset + 2],
                    payload[offset + 3],
                ]);
                offset += 4;

                let format =
                    i16::from_be_bytes([payload[offset], payload[offset + 1]]);
                offset += 2;

                fields.push(FieldDescription {
                    name,
                    table_oid,
                    column_id,
                    type_oid,
                    type_size,
                    type_modifier,
                    format,
                });
            }

            Ok(BackendMessage::RowDescription { fields })
        }

        // 'D' — DataRow
        b'D' => {
            if payload.len() < 2 {
                return Ok(BackendMessage::Unknown {
                    tag,
                    payload: payload.to_vec(),
                });
            }
            let num_cols = i16::from_be_bytes([payload[0], payload[1]]) as usize;
            let mut offset = 2;
            let mut values = Vec::with_capacity(num_cols);

            for _ in 0..num_cols {
                if offset + 4 > payload.len() {
                    break;
                }
                let col_len = i32::from_be_bytes([
                    payload[offset],
                    payload[offset + 1],
                    payload[offset + 2],
                    payload[offset + 3],
                ]);
                offset += 4;
                if col_len == -1 {
                    values.push(None);
                } else {
                    let len = col_len as usize;
                    if offset + len <= payload.len() {
                        values.push(Some(payload[offset..offset + len].to_vec()));
                        offset += len;
                    }
                }
            }

            Ok(BackendMessage::DataRow { values })
        }

        // 'C' — CommandComplete
        b'C' => {
            let (tag_str, _) = read_cstring(payload)?;
            Ok(BackendMessage::CommandComplete { tag: tag_str })
        }

        // 'E' — ErrorResponse
        b'E' => {
            let mut fields = HashMap::new();
            let mut offset = 0;

            while offset < payload.len() {
                let field_type = payload[offset];
                offset += 1;
                if field_type == 0 {
                    break; // End of fields
                }
                let (value, consumed) = read_cstring(&payload[offset..])?;
                offset += consumed;
                fields.insert(field_type, value);
            }

            Ok(BackendMessage::ErrorResponse { fields })
        }

        // '1' — ParseComplete
        b'1' => Ok(BackendMessage::ParseComplete),

        // '2' — BindComplete
        b'2' => Ok(BackendMessage::BindComplete),

        // 'S' — ParameterStatus
        b'S' => {
            let (name, consumed) = read_cstring(payload)?;
            let (value, _) = read_cstring(&payload[consumed..])?;
            Ok(BackendMessage::ParameterStatus { name, value })
        }

        // 'K' — BackendKeyData
        b'K' => {
            if payload.len() < 8 {
                return Ok(BackendMessage::Unknown {
                    tag,
                    payload: payload.to_vec(),
                });
            }
            let pid = i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
            let secret =
                i32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
            Ok(BackendMessage::BackendKeyData { pid, secret })
        }

        _ => Ok(BackendMessage::Unknown {
            tag,
            payload: payload.to_vec(),
        }),
    }
}

/// Parse an Authentication sub-message from the 'R' tag payload.
fn parse_auth_message(payload: &[u8]) -> Result<BackendMessage, WireError> {
    if payload.len() < 4 {
        return Ok(BackendMessage::Unknown {
            tag: b'R',
            payload: payload.to_vec(),
        });
    }

    let auth_type = i32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);

    match auth_type {
        0 => Ok(BackendMessage::AuthenticationOk),
        3 => Ok(BackendMessage::AuthenticationCleartextPassword),
        5 => {
            // MD5 password — 4-byte salt follows
            if payload.len() < 8 {
                return Err(WireError::InsufficientData {
                    needed: 8,
                    available: payload.len(),
                });
            }
            let mut salt = [0u8; 4];
            salt.copy_from_slice(&payload[4..8]);
            Ok(BackendMessage::AuthenticationMD5Password { salt })
        }
        10 => {
            // SASL — list of mechanism names (null-terminated strings, double-null terminated)
            let mut mechanisms = Vec::new();
            let mut offset = 4;
            while offset < payload.len() {
                if payload[offset] == 0 {
                    break;
                }
                let (mechanism, consumed) = read_cstring(&payload[offset..])?;
                mechanisms.push(mechanism);
                offset += consumed;
            }
            Ok(BackendMessage::AuthenticationSASL { mechanisms })
        }
        11 => {
            // SASL Continue
            Ok(BackendMessage::AuthenticationSASLContinue(
                payload[4..].to_vec(),
            ))
        }
        12 => {
            // SASL Final
            Ok(BackendMessage::AuthenticationSASLFinal(
                payload[4..].to_vec(),
            ))
        }
        _ => Ok(BackendMessage::Unknown {
            tag: b'R',
            payload: payload.to_vec(),
        }),
    }
}

// ---------------------------------------------------------------------------
// Serialization helpers (for forwarding / re-encoding)
// ---------------------------------------------------------------------------

/// Encode a startup message into bytes.
pub fn encode_startup_message(user: &str, database: &str, params: &HashMap<String, String>) -> BytesMut {
    let mut body = BytesMut::new();
    body.put_i32(PROTOCOL_VERSION_3);

    body.put_slice(b"user\0");
    body.put_slice(user.as_bytes());
    body.put_u8(0);

    body.put_slice(b"database\0");
    body.put_slice(database.as_bytes());
    body.put_u8(0);

    for (key, value) in params {
        body.put_slice(key.as_bytes());
        body.put_u8(0);
        body.put_slice(value.as_bytes());
        body.put_u8(0);
    }

    body.put_u8(0); // Final null terminator

    let length = (body.len() + 4) as i32; // +4 for the length field itself
    let mut msg = BytesMut::with_capacity(4 + body.len());
    msg.put_i32(length);
    msg.put(body);
    msg
}

/// Encode the 'N' response to deny an SSL request.
pub fn encode_ssl_deny() -> BytesMut {
    let mut buf = BytesMut::with_capacity(1);
    buf.put_u8(b'N');
    buf
}

/// Encode a Postgres ErrorResponse message suitable for returning to a client
/// before the connection enters the normal message loop. Used by the listener
/// to reject new clients cleanly when the connection cap is exhausted
/// (items A.1 + D of round-1 overload protection).
///
/// The error is followed by a zero-length ReadyForQuery — we don't bother
/// sending RFQ because we close the socket immediately, and most pg clients
/// handle a plain ErrorResponse + TCP close correctly (they raise the error
/// and exit).
///
/// Fields emitted:
/// - `S` — severity ("ERROR")
/// - `C` — SQLSTATE code (passed in, e.g. `"53300"` for too_many_connections)
/// - `M` — human-readable message
///
/// Format per the Postgres wire-protocol docs:
///   'E' | int32(length) | (field_code u8 | cstring)* | 0x00
pub fn encode_error_response(sqlstate: &str, message: &str) -> BytesMut {
    // Body: concatenation of (1-byte field code || nul-terminated string),
    // terminated by a single 0 byte.
    let mut body = BytesMut::new();

    body.put_u8(b'S');
    body.put_slice(b"ERROR");
    body.put_u8(0);

    body.put_u8(b'C');
    body.put_slice(sqlstate.as_bytes());
    body.put_u8(0);

    body.put_u8(b'M');
    body.put_slice(message.as_bytes());
    body.put_u8(0);

    // Terminating zero byte for the field list.
    body.put_u8(0);

    // Header: 'E' || length (4 bytes, includes the length field itself but
    // NOT the 'E' tag byte).
    let length = (body.len() as i32) + 4;
    let mut msg = BytesMut::with_capacity(1 + body.len() + 4);
    msg.put_u8(b'E');
    msg.put_i32(length);
    msg.put(body);
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a startup message buffer by hand.
    fn build_startup(user: &str, db: &str) -> Vec<u8> {
        let encoded = encode_startup_message(user, db, &HashMap::new());
        encoded.to_vec()
    }

    /// Build a tagged message: tag(1) || length(4) || payload
    fn build_tagged(tag: u8, payload: &[u8]) -> Vec<u8> {
        let length = (payload.len() as i32) + 4; // length includes itself
        let mut buf = Vec::with_capacity(1 + 4 + payload.len());
        buf.push(tag);
        buf.extend_from_slice(&length.to_be_bytes());
        buf.extend_from_slice(payload);
        buf
    }

    // --- Startup message tests ---

    #[test]
    fn parse_startup_message() {
        let buf = build_startup("admin", "mydb");
        let msg = parse_initial_message(&buf).unwrap();
        match msg {
            InitialMessage::Startup(FrontendMessage::StartupMessage {
                user,
                database,
                ..
            }) => {
                assert_eq!(user, "admin");
                assert_eq!(database, "mydb");
            }
            other => panic!("expected StartupMessage, got {other:?}"),
        }
    }

    #[test]
    fn parse_startup_default_database() {
        // When database is not specified, it defaults to the username
        let mut body = BytesMut::new();
        body.put_i32(PROTOCOL_VERSION_3);
        body.put_slice(b"user\0testuser\0");
        body.put_u8(0); // terminator

        let length = (body.len() + 4) as i32;
        let mut buf = BytesMut::new();
        buf.put_i32(length);
        buf.put(body);

        let msg = parse_initial_message(&buf).unwrap();
        match msg {
            InitialMessage::Startup(FrontendMessage::StartupMessage {
                user, database, ..
            }) => {
                assert_eq!(user, "testuser");
                assert_eq!(database, "testuser");
            }
            other => panic!("expected StartupMessage, got {other:?}"),
        }
    }

    #[test]
    fn parse_ssl_request() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&8i32.to_be_bytes());
        buf.extend_from_slice(&SSL_REQUEST_CODE.to_be_bytes());
        let msg = parse_initial_message(&buf).unwrap();
        assert!(matches!(msg, InitialMessage::SslRequest));
    }

    // --- Simple query test ---

    #[test]
    fn parse_simple_query() {
        let sql = "SELECT * FROM users WHERE id = 1";
        let mut payload = Vec::new();
        payload.extend_from_slice(sql.as_bytes());
        payload.push(0); // null terminator

        let buf = build_tagged(b'Q', &payload);
        let msg = parse_frontend_message(&buf).unwrap();
        match msg {
            FrontendMessage::Query { sql: parsed_sql } => {
                assert_eq!(parsed_sql, sql);
            }
            other => panic!("expected Query, got {other:?}"),
        }
    }

    // --- Parse message test ---

    #[test]
    fn parse_parse_message() {
        let mut payload = Vec::new();
        // Statement name (empty = unnamed)
        payload.push(0);
        // SQL
        payload.extend_from_slice(b"SELECT $1::int");
        payload.push(0);
        // Number of parameter types
        payload.extend_from_slice(&1i16.to_be_bytes());
        // OID for int4 = 23
        payload.extend_from_slice(&23i32.to_be_bytes());

        let buf = build_tagged(b'P', &payload);
        let msg = parse_frontend_message(&buf).unwrap();
        match msg {
            FrontendMessage::Parse {
                name,
                sql,
                param_types,
            } => {
                assert_eq!(name, "");
                assert_eq!(sql, "SELECT $1::int");
                assert_eq!(param_types, vec![23]);
            }
            other => panic!("expected Parse, got {other:?}"),
        }
    }

    // --- Terminate test ---

    #[test]
    fn parse_terminate() {
        let buf = build_tagged(b'X', &[]);
        let msg = parse_frontend_message(&buf).unwrap();
        assert_eq!(msg, FrontendMessage::Terminate);
    }

    // --- Backend auth messages ---

    #[test]
    fn parse_auth_ok() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&0i32.to_be_bytes()); // auth type 0 = OK
        let buf = build_tagged(b'R', &payload);
        let msg = parse_backend_message(&buf).unwrap();
        assert_eq!(msg, BackendMessage::AuthenticationOk);
    }

    #[test]
    fn parse_auth_md5() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&5i32.to_be_bytes()); // auth type 5 = MD5
        payload.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // salt
        let buf = build_tagged(b'R', &payload);
        let msg = parse_backend_message(&buf).unwrap();
        match msg {
            BackendMessage::AuthenticationMD5Password { salt } => {
                assert_eq!(salt, [0xDE, 0xAD, 0xBE, 0xEF]);
            }
            other => panic!("expected MD5, got {other:?}"),
        }
    }

    #[test]
    fn parse_auth_cleartext() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&3i32.to_be_bytes());
        let buf = build_tagged(b'R', &payload);
        let msg = parse_backend_message(&buf).unwrap();
        assert_eq!(msg, BackendMessage::AuthenticationCleartextPassword);
    }

    #[test]
    fn parse_auth_sasl() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&10i32.to_be_bytes()); // SASL
        payload.extend_from_slice(b"SCRAM-SHA-256\0");
        payload.push(0); // end of mechanism list
        let buf = build_tagged(b'R', &payload);
        let msg = parse_backend_message(&buf).unwrap();
        match msg {
            BackendMessage::AuthenticationSASL { mechanisms } => {
                assert_eq!(mechanisms, vec!["SCRAM-SHA-256"]);
            }
            other => panic!("expected SASL, got {other:?}"),
        }
    }

    // --- ReadyForQuery ---

    #[test]
    fn parse_ready_for_query() {
        let buf = build_tagged(b'Z', &[b'I']);
        let msg = parse_backend_message(&buf).unwrap();
        assert_eq!(msg, BackendMessage::ReadyForQuery { status: b'I' });
    }

    // --- CommandComplete ---

    #[test]
    fn parse_command_complete() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"SELECT 5");
        payload.push(0);
        let buf = build_tagged(b'C', &payload);
        let msg = parse_backend_message(&buf).unwrap();
        assert_eq!(
            msg,
            BackendMessage::CommandComplete {
                tag: "SELECT 5".to_string()
            }
        );
    }

    // --- ParameterStatus ---

    #[test]
    fn parse_parameter_status() {
        let mut payload = Vec::new();
        payload.extend_from_slice(b"server_encoding\0UTF8\0");
        let buf = build_tagged(b'S', &payload);
        let msg = parse_backend_message(&buf).unwrap();
        assert_eq!(
            msg,
            BackendMessage::ParameterStatus {
                name: "server_encoding".to_string(),
                value: "UTF8".to_string(),
            }
        );
    }

    // --- BackendKeyData ---

    #[test]
    fn parse_backend_key_data() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&42i32.to_be_bytes());
        payload.extend_from_slice(&12345i32.to_be_bytes());
        let buf = build_tagged(b'K', &payload);
        let msg = parse_backend_message(&buf).unwrap();
        assert_eq!(
            msg,
            BackendMessage::BackendKeyData {
                pid: 42,
                secret: 12345
            }
        );
    }

    // --- frame_length ---

    #[test]
    fn frame_length_startup() {
        let buf = build_startup("user", "db");
        assert_eq!(frame_length(&buf, true), Some(buf.len()));
    }

    #[test]
    fn frame_length_tagged() {
        let buf = build_tagged(b'Q', b"SELECT 1\0");
        assert_eq!(frame_length(&buf, false), Some(buf.len()));
    }

    #[test]
    fn frame_length_incomplete() {
        assert_eq!(frame_length(&[0, 0], true), None);
        assert_eq!(frame_length(&[b'Q', 0, 0], false), None);
    }

    // --- ErrorResponse ---

    #[test]
    fn parse_error_response() {
        let mut payload = Vec::new();
        payload.push(b'S'); // Severity
        payload.extend_from_slice(b"ERROR\0");
        payload.push(b'M'); // Message
        payload.extend_from_slice(b"relation \"foo\" does not exist\0");
        payload.push(0); // terminator

        let buf = build_tagged(b'E', &payload);
        let msg = parse_backend_message(&buf).unwrap();
        match msg {
            BackendMessage::ErrorResponse { fields } => {
                assert_eq!(fields.get(&b'S'), Some(&"ERROR".to_string()));
                assert_eq!(
                    fields.get(&b'M'),
                    Some(&"relation \"foo\" does not exist".to_string())
                );
            }
            other => panic!("expected ErrorResponse, got {other:?}"),
        }
    }

    // --- Encode/decode roundtrip ---

    #[test]
    fn startup_encode_decode_roundtrip() {
        let mut params = HashMap::new();
        params.insert("application_name".to_string(), "psql".to_string());
        let encoded = encode_startup_message("admin", "mydb", &params);
        let msg = parse_initial_message(&encoded).unwrap();
        match msg {
            InitialMessage::Startup(FrontendMessage::StartupMessage {
                user,
                database,
                params: decoded_params,
            }) => {
                assert_eq!(user, "admin");
                assert_eq!(database, "mydb");
                assert_eq!(
                    decoded_params.get("application_name"),
                    Some(&"psql".to_string())
                );
            }
            other => panic!("expected StartupMessage, got {other:?}"),
        }
    }
}
