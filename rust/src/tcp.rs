use etherparse::TcpHeaderSlice;
use log::debug;

use self::model::TcpConnectionKey;

pub mod connection;
pub mod model;

pub(crate) fn log_tcp_header<'a>(tcp_connection_key: &TcpConnectionKey, tcp_header: &TcpHeaderSlice<'a>, payload_length: usize) {
    debug!(
            ">>>> Tcp connection [{}] receive tcp packet, sequence number: {}, ack number: {}, sync: {}, ack: {}, psh:{}, fin: {}, rst: {}, payload size: {payload_length}",
        tcp_connection_key,
        tcp_header.sequence_number(),
        tcp_header.acknowledgment_number(),
        tcp_header.syn(),
        tcp_header.ack(),
        tcp_header.psh(),
        tcp_header.fin(),
        tcp_header.rst(),
    );
}
