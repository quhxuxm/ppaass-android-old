use std::{
    fmt::{Debug, Display, Formatter},
    net::Ipv4Addr,
};

mod connection;

pub(crate) use connection::TcpConnection;
pub(crate) use connection::TcpConnectionTcpPacketInputHandle;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct TcpConnectionId {
    src_addr: Ipv4Addr,
    dst_addr: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
}

impl TcpConnectionId {
    pub(crate) fn new(src_addr: Ipv4Addr, src_port: u16, dst_addr: Ipv4Addr, dst_port: u16) -> Self {
        Self {
            src_addr,
            dst_addr,
            src_port,
            dst_port,
        }
    }
}

impl Debug for TcpConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}:{}->{}:{}]", self.src_addr, self.src_port, self.dst_addr, self.dst_port)
    }
}

impl Display for TcpConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

#[derive(Debug, PartialEq, Eq, Default, Clone, Copy)]
pub(crate) enum TcpConnectionStatus {
    #[default]
    Listen,
    Closed,

    SynReceived,
    Established,
    FinWait1,
    FinWait2,

    CloseWait,
    LastAck,
    TimeWait,
}

impl Display for TcpConnectionStatus {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match *self {
            TcpConnectionStatus::Closed => write!(f, "CLOSED"),
            TcpConnectionStatus::Listen => write!(f, "LISTEN"),
            TcpConnectionStatus::SynReceived => write!(f, "SYN-RECEIVED"),
            TcpConnectionStatus::Established => write!(f, "ESTABLISHED"),
            TcpConnectionStatus::FinWait1 => write!(f, "FIN-WAIT-1"),
            TcpConnectionStatus::FinWait2 => write!(f, "FIN-WAIT-2"),
            TcpConnectionStatus::CloseWait => write!(f, "CLOSE-WAIT"),
            TcpConnectionStatus::LastAck => write!(f, "LAST-ACK"),
            TcpConnectionStatus::TimeWait => write!(f, "TIME-WAIT"),
        }
    }
}

#[derive(Clone)]
#[non_exhaustive]
struct TransmissionControlBlock {
    pub initial_sequence_number: u32,
    pub initial_acknowledgement_number: u32,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub status: TcpConnectionStatus,
    pub rx_window_start: usize,
    pub tx_window_start: usize,
    pub rx_window_size: u16,
    pub tx_window_size: u16,
    pub rx_window: Vec<u8>,
    pub tx_window: Vec<u8>,
}

impl Default for TransmissionControlBlock {
    fn default() -> Self {
        Self {
            initial_sequence_number: Default::default(),
            initial_acknowledgement_number: Default::default(),
            sequence_number: Default::default(),
            acknowledgment_number: Default::default(),
            status: Default::default(),
            rx_window: vec![0u8; u16::MAX as usize],
            tx_window: vec![0u8; u16::MAX as usize],
            rx_window_size: u16::MAX,
            tx_window_size: u16::MAX,
        }
    }
}

impl Debug for TransmissionControlBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TCB")
            .field("relative_sequence_number", &(self.sequence_number - self.initial_sequence_number))
            .field(
                "relative_acknowledgement_number",
                &(self.acknowledgment_number - self.initial_acknowledgement_number),
            )
            .field("sequence_number", &self.sequence_number)
            .field("acknowledgment_number", &self.acknowledgment_number)
            .field("rx_window_size", &self.rx_window_size)
            .field("tx_window_size", &self.tx_window_size)
            .field("status", &self.status)
            .finish()
    }
}

impl Display for TransmissionControlBlock {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", &self)
    }
}
