use std::{
    fmt::Debug,
    net::{IpAddr, SocketAddr},
    os::fd::AsRawFd,
    sync::Arc,
    time::Duration,
};

use crate::{protect_socket, tcp};

use super::{TcpConnectionId, TcpConnectionStatus, TransmissionControlBlock};
use anyhow::{anyhow, Result};
use etherparse::{PacketBuilder, TcpHeader};
use log::{debug, error, trace};

use rand::random;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
    task::JoinHandle,
    time::timeout,
};

const IP_PACKET_TTL: u8 = 64;
const MAX_TCP_PACKET_PAYLOAD_SIZE: usize = 1460;
const WINDOW_SIZE: u16 = 65535;
const CONNECT_TO_DST_TIMEOUT: u64 = 20;

#[derive(Debug, Clone)]
pub(crate) struct TcpConnectionTcpPacketInputHandle {
    tcp_packet_input_sender: Sender<(TcpHeader, Vec<u8>)>,
}

impl TcpConnectionTcpPacketInputHandle {
    pub(crate) async fn handle_tun_input(&self, tcp_header: TcpHeader, payload: &[u8]) -> Result<()> {
        self.tcp_packet_input_sender.send((tcp_header, payload.to_vec())).await?;
        Ok(())
    }
}

pub(crate) struct TcpConnection {
    id: TcpConnectionId,
    dst_write: Option<OwnedWriteHalf>,
    tcp_packet_input_receiver: Receiver<(TcpHeader, Vec<u8>)>,
    ip_packet_output_sender: Sender<Vec<u8>>,
    tcp_packet_input_handle: TcpConnectionTcpPacketInputHandle,
    tcb: Arc<Mutex<TransmissionControlBlock>>,
}

impl Drop for TcpConnection {
    fn drop(&mut self) {
        debug!("#### Tcp connection [{}] dropped.", self.id)
    }
}

impl Debug for TcpConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpConnection").field("id", &self.id).field("tcb", &self.tcb).finish()
    }
}

impl TcpConnection {
    pub(crate) fn new(id: TcpConnectionId, ip_packet_output_sender: Sender<Vec<u8>>) -> Self {
        trace!(">>>> Create new tcp connection [{id}]");
        let (tcp_packet_input_sender, tcp_packet_input_receiver) = channel(1024);

        let tcp_packet_input_handle = TcpConnectionTcpPacketInputHandle { tcp_packet_input_sender };
        Self {
            id,
            tcp_packet_input_handle,
            tcp_packet_input_receiver,
            ip_packet_output_sender,
            tcb: Default::default(),
            dst_write: None,
        }
    }

    pub(crate) fn clone_input_handle(&self) -> TcpConnectionTcpPacketInputHandle {
        self.tcp_packet_input_handle.clone()
    }

    pub(crate) async fn process(&mut self) -> Result<()> {
        if let Err(e) = self.concrete_process().await {
            let tcb = self.tcb.lock().await;
            error!(
                "<<<< Tcp connection [{}] fail to process state machine because of error, current tcb: {tcb:?}, error: {e:?}",
                self.id
            );
            Self::send_rst_ack_to_tun(self.id, tcb.sequence_number, tcb.acknowledgment_number, &self.ip_packet_output_sender).await?;
        }
        Ok(())
    }

    async fn concrete_process(&mut self) -> Result<()> {
        loop {
            let (tcp_header, payload) = match self.tcp_packet_input_receiver.recv().await {
                Some(value) => value,
                None => {
                    debug!(">>>> Tcp connection [{}] complete to read tun data.", self.id);
                    break;
                },
            };

            let tcp_connection_status = {
                let tcb = self.tcb.lock().await;
                debug!(
                    ">>>> Tcp connection [{}] receive: {tcp_header:?}, payload size={}, current tcb: {:?}",
                    self.id,
                    payload.len(),
                    &tcb
                );
                tcb.status
            };

            match tcp_connection_status {
                TcpConnectionStatus::Listen => {
                    Self::on_listen(self.id, self.tcb.clone(), &self.ip_packet_output_sender, tcp_header).await?;
                    continue;
                },
                TcpConnectionStatus::SynReceived => {
                    let dst_write = Self::on_syn_received(self.id, self.tcb.clone(), &self.ip_packet_output_sender, tcp_header).await?;
                    self.dst_write = Some(dst_write);
                    continue;
                },
                TcpConnectionStatus::Established => {
                    Self::on_established(
                        self.id,
                        self.tcb.clone(),
                        &self.ip_packet_output_sender,
                        self.dst_write.as_mut().ok_or(anyhow!(
                            ">>>> Tcp connection [{}] can not handle established status because of no destination write.",
                            self.id
                        ))?,
                        tcp_header,
                        payload,
                    )
                    .await?;
                    continue;
                },
                TcpConnectionStatus::Closed => {
                    return Err(anyhow!("Tcp connection [{}] in Closed status should not handle any tcp packet.", self.id));
                },
                TcpConnectionStatus::FinWait1 => {
                    Self::on_fin_wait1(self.id, self.tcb.clone(), &self.ip_packet_output_sender, tcp_header).await?;
                    continue;
                },
                TcpConnectionStatus::FinWait2 => {
                    Self::on_fin_wait2(self.id, self.tcb.clone(), &self.ip_packet_output_sender, tcp_header).await?;
                    continue;
                },
                TcpConnectionStatus::CloseWait => {
                    Self::on_close_wait(self.id, self.tcb.clone(), &self.ip_packet_output_sender, tcp_header).await?;
                    continue;
                },
                TcpConnectionStatus::LastAck => {
                    Self::on_last_ack(self.id, self.tcb.clone(), &self.ip_packet_output_sender, tcp_header).await?;
                    continue;
                },
                TcpConnectionStatus::TimeWait => {
                    Self::on_time_wait(self.id, self.tcb.clone(), &self.ip_packet_output_sender, tcp_header).await?;
                    continue;
                },
            }
        }
        Ok(())
    }

    async fn on_listen(
        id: TcpConnectionId, tcb: Arc<Mutex<TransmissionControlBlock>>, ip_packet_output_sender: &Sender<Vec<u8>>, tcp_header: TcpHeader,
    ) -> Result<()> {
        let mut tcb = tcb.lock().await;
        if !tcp_header.syn {
            error!(
                ">>>> Tcp connection [{}] fail to process [Listen], expect syn=true, but get: {tcp_header:?}",
                id
            );
            return Err(anyhow!(
                "Tcp connection [{}] fail to process [Listen], expect syn=true, but get: {tcp_header:?}",
                id
            ));
        }

        let iss = random::<u32>();

        tcb.status = TcpConnectionStatus::SynReceived;

        tcb.sequence_number = iss;

        Self::send_syn_ack_to_tun(id, tcb.sequence_number, tcp_header.sequence_number + 1, ip_packet_output_sender).await?;

        debug!("<<<< Tcp connection [{id}] switch to [SynReceived], current tcb: {tcb:?}",);
        Ok(())
    }

    async fn on_syn_received(
        id: TcpConnectionId, tbc: Arc<Mutex<TransmissionControlBlock>>, ip_packet_output_sender: &Sender<Vec<u8>>, tcp_header: TcpHeader,
    ) -> Result<OwnedWriteHalf> {
        if tcp_header.syn {
            error!(">>>> Tcp connection [{id}] fail to process [SynReceived], expect syn=false, but get: {tcp_header:?}",);
            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [SynReceived], expect syn=false, but get: {tcp_header:?}",
            ));
        }
        if !tcp_header.ack {
            // In SynReceived status, connection should receive a ack.
            error!(">>>> Tcp connection [{id}] fail to process [SynReceived], expect ack=true, but get: {tcp_header:?}",);
            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [SynReceived], expect ack=true, but get: {tcp_header:?}",
            ));
        }
        // Process the connection when the connection in SynReceived status

        let mut tcb = tbc.lock().await;
        if tcp_header.acknowledgment_number != tcb.sequence_number + 1 {
            error!(
                ">>>> Tcp connection [{id}] fail to process [SynReceived], expect sequence number={}, but get: {tcp_header:?}",
                tcb.sequence_number + 1
            );
            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [SynReceived], expect sequence number={}, but get: {tcp_header:?}",
                tcb.sequence_number + 1,
            ));
        }

        let dst_socket = tokio::net::TcpSocket::new_v4()?;
        let dst_socket_raw_fd = dst_socket.as_raw_fd();
        protect_socket(dst_socket_raw_fd)?;
        let dst_socket_addr = SocketAddr::new(IpAddr::V4(id.dst_addr), id.dst_port);
        let dst_tcp_stream = timeout(Duration::from_secs(CONNECT_TO_DST_TIMEOUT), dst_socket.connect(dst_socket_addr)).await??;

        debug!(">>>> Tcp connection [{}] connect to destination success.", id);
        let (dst_read, dst_write) = dst_tcp_stream.into_split();

        Self::start_dst_relay(id, ip_packet_output_sender.clone(), dst_read, tbc.clone()).await;

        tcb.status = TcpConnectionStatus::Established;

        tcb.sequence_number += 1;
        tcb.acknowledgment_number = tcp_header.sequence_number;

        debug!(">>>> Tcp connection [{id}] switch to [Established], current tcb: {tcb:?}",);
        Ok(dst_write)
    }

    async fn on_established(
        id: TcpConnectionId, tbc: Arc<Mutex<TransmissionControlBlock>>, ip_packet_output_sender: &Sender<Vec<u8>>, dst_write: &mut OwnedWriteHalf,
        tcp_header: TcpHeader, payload: Vec<u8>,
    ) -> Result<()> {
        // Process the connection when the connection in Established status
        let mut tcb = tbc.lock().await;
        if tcb.sequence_number != tcp_header.acknowledgment_number {
            error!(
                ">>>> Tcp connection [{id}] fail to process [Established], expect sequence number: {}, but get: {tcp_header:?}",
                tcb.sequence_number
            );

            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [Established], expect sequence number: {}, but get: {tcp_header:?}",
                tcb.sequence_number
            ));
        }

        if tcb.acknowledgment_number != tcp_header.sequence_number {
            error!(
                ">>>> Tcp connection [{id}] fail to process [Established], expect acknowledgment number: {}, but get: {tcp_header:?}",
                tcb.acknowledgment_number
            );

            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [Established], expect acknowledgment number: {}, but get: {tcp_header:?}",
                tcb.acknowledgment_number
            ));
        }

        // Relay from device to destination.
        let relay_data_length = payload.len();
        let relay_data_length: u32 = match relay_data_length.try_into() {
            Ok(relay_data_length) => relay_data_length,
            Err(e) => {
                error!(">>>> Tcp connection [{id}] fail convert tun data length to u32 because of error: {e:?}",);
                return Err(anyhow!("Tcp connection [{id}] fail convert tun data length to u32 because of error.",));
            },
        };
        if relay_data_length > 0 {
            if let Err(e) = dst_write.write(&payload).await {
                error!(">>>> Tcp connection [{id}] fail to relay tun data to destination because of error(write): {e:?}",);
                return Err(anyhow!(
                    "Tcp connection [{id}] fail to relay tun data to destination because of error(write): {e:?}",
                ));
            };
            if let Err(e) = dst_write.flush().await {
                error!(">>>> Tcp connection [{id}] fail to relay tun data to destination because of error(flush): {e:?}",);
                return Err(anyhow!(
                    "Tcp connection [{id}] fail to relay tun data to destination because of error(flush): {e:?}",
                ));
            };

            debug!(
                ">>>> Tcp connection [{id}] success relay tun data [size={}] to destination:\n{}\n",
                relay_data_length,
                pretty_hex::pretty_hex(&payload)
            );
        }

        if tcp_header.fin {
            tcb.status = TcpConnectionStatus::CloseWait;

            debug!(">>>> Tcp connection [{id}] in [Established] status, receive FIN, switch to [CloseWait], current tcb: {tcb:?}",);
            Self::send_ack_to_tun(
                id,
                tcb.sequence_number,
                tcp_header.sequence_number + relay_data_length + 1,
                ip_packet_output_sender,
                None,
            )
            .await?;
            tcb.acknowledgment_number = tcp_header.sequence_number + relay_data_length + 1;

            tcb.status = TcpConnectionStatus::LastAck;

            debug!(">>>> Tcp connection [{id}] in [CloseWait] status, switch to [LastAck], current tcb: {tcb:?}",);
            Self::send_fin_ack_to_tun(id, tcb.sequence_number, tcb.acknowledgment_number, ip_packet_output_sender).await?;
            return Ok(());
        }

        // Self::send_ack_to_tun(
        //     id,
        //     tcb.sequence_number,
        //     tcp_header.sequence_number + relay_data_length,
        //     ip_packet_output_sender,
        //     None,
        // )
        // .await?;
        tcb.acknowledgment_number = tcp_header.sequence_number + relay_data_length;
        Ok(())
    }

    async fn on_fin_wait1(
        id: TcpConnectionId, tbc: Arc<Mutex<TransmissionControlBlock>>, ip_packet_output_sender: &Sender<Vec<u8>>, tcp_header: TcpHeader,
    ) -> Result<()> {
        let mut tcb = tbc.lock().await;
        if !tcp_header.ack {
            error!(">>>> Tcp connection [{id}] fail to process [FinWait1], expect ack=true, but get: {tcp_header:?}",);
            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [FinWait1], expect ack=true, but get: {tcp_header:?}",
            ));
        }
        if tcb.sequence_number + 1 < tcp_header.acknowledgment_number {
            error!(
                ">>>> Tcp connection [{id}] fail to process [FinWait1], expect acknowledgment number={}, but get: {tcp_header:?}",
                tcb.sequence_number + 1
            );
            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [FinWait1], expect acknowledgment number={}, but get: {tcp_header:?}",
                tcb.sequence_number + 1,
            ));
        }
        if tcb.acknowledgment_number != tcp_header.sequence_number {
            error!(
                ">>>> Tcp connection [{id}] fail to process [FinWait1], expect sequence number={}, but get: {tcp_header:?}",
                tcb.acknowledgment_number
            );
            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [FinWait1], expect sequence number={}, but get: {tcp_header:?}",
                tcb.acknowledgment_number
            ));
        }
        tcb.status = TcpConnectionStatus::FinWait2;
        tcb.sequence_number += 1;

        debug!(">>>> Tcp connection [{id}] switch to [FinWait2], current tcb: {tcb:?}",);

        Ok(())
    }

    async fn on_fin_wait2(
        id: TcpConnectionId, tcb: Arc<Mutex<TransmissionControlBlock>>, ip_packet_output_sender: &Sender<Vec<u8>>, tcp_header: TcpHeader,
    ) -> Result<()> {
        let tcb_for_time_wait = tcb.clone();
        let mut tcb = tcb.lock().await;
        if !tcp_header.fin {
            error!(">>>> Tcp connection [{id}] fail to process [FinWait2], expect fin=true, but get: {tcp_header:?}",);
            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [FinWait2], expect fin=true, but get: {tcp_header:?}",
            ));
        }
        if !tcp_header.ack {
            error!(">>>> Tcp connection [{id}] fail to process [FinWait2], expect ack=true, but get: {tcp_header:?}",);
            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [FinWait2], expect ack=true, but get: {tcp_header:?}",
            ));
        }
        if tcb.sequence_number < tcp_header.acknowledgment_number {
            error!(
                ">>>> Tcp connection [{id}] fail to process [FinWait2], expect acknowledgement number={}, but get: {tcp_header:?}",
                tcb.sequence_number
            );
            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [FinWait2], expect acknowledgement number={}, but get: {tcp_header:?}",
                tcb.sequence_number
            ));
        }
        if tcb.acknowledgment_number != tcp_header.sequence_number {
            error!(
                ">>>> Tcp connection [{id}] fail to process [FinWait2], expect sequence number={}, but get: {tcp_header:?}",
                tcb.acknowledgment_number
            );
            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [FinWait2], expect sequence number={}, but get: {tcp_header:?}",
                tcb.acknowledgment_number
            ));
        }

        tcb.status = TcpConnectionStatus::TimeWait;

        tokio::spawn(async move {
            debug!(">>>> Tcp connection [{id}] in TimeWait status begin 2ML task.");
            let mut tcb = tcb_for_time_wait.lock().await;
            debug!(">>>> Tcp connection [{id}] in TimeWait status doing 2ML task, current connection: {tcb:?}",);
            tcb.status = TcpConnectionStatus::Closed;
            debug!(">>>> Tcp connection [{id}] complete 2ML task switch to [Closed], current tcb: {tcb:?}",);
        });

        debug!(">>>> Tcp connection [{id}] switch to [TimeWait], current tcb: {tcb:?}",);
        Self::send_ack_to_tun(id, tcb.sequence_number, tcp_header.sequence_number + 1, ip_packet_output_sender, None).await?;
        tcb.acknowledgment_number = tcp_header.sequence_number + 1;
        Ok(())
    }

    async fn on_last_ack(
        id: TcpConnectionId, tbc: Arc<Mutex<TransmissionControlBlock>>, ip_packet_output_sender: &Sender<Vec<u8>>, tcp_header: TcpHeader,
    ) -> Result<()> {
        let mut tcb = tbc.lock().await;
        if !tcp_header.ack {
            error!(">>>> Tcp connection [{id}] fail to process [LastAck], expect ack=true, but get: {tcp_header:?}",);
            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [LastAck], expect ack=true,but get: {tcp_header:?}",
            ));
        }
        if tcb.acknowledgment_number != tcp_header.sequence_number {
            error!(
                ">>>> Tcp connection [{id}] fail to process [LastAck], expect sequence number={}, but get: {tcp_header:?}",
                tcb.acknowledgment_number
            );
            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [LastAck], expect sequence number={}, but get: {tcp_header:?}",
                tcb.acknowledgment_number
            ));
        }
        if tcb.sequence_number < tcp_header.acknowledgment_number {
            error!(
                ">>>> Tcp connection [{id}] fail to process [LastAck], expect acknowledgment number={}, but get: {tcp_header:?}",
                tcb.sequence_number
            );
            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [LastAck], expect acknowledgment number={}, but get: {tcp_header:?}",
                tcb.sequence_number
            ));
        }
        tcb.status = TcpConnectionStatus::Closed;
        debug!(">>>> Tcp connection [{id}] switch to [Closed] status, remove from the connection repository.");
        Ok(())
    }

    async fn on_time_wait(
        id: TcpConnectionId, tbc: Arc<Mutex<TransmissionControlBlock>>, ip_packet_output_sender: &Sender<Vec<u8>>, tcp_header: TcpHeader,
    ) -> Result<()> {
        let tcb = tbc.lock().await;
        Self::send_ack_to_tun(id, tcb.sequence_number, tcb.acknowledgment_number, ip_packet_output_sender, None).await?;
        debug!(">>>> Tcp connection [{id}] keep in [TimeWait], current tcb: {tcb:?}");
        Ok(())
    }

    async fn on_close_wait(
        id: TcpConnectionId, tbc: Arc<Mutex<TransmissionControlBlock>>, ip_packet_output_sender: &Sender<Vec<u8>>, tcp_header: TcpHeader,
    ) -> Result<()> {
        let mut tcb = tbc.lock().await;
        debug!(">>>> Tcp connection [{id}] in [CloseWait] status, switch to [LastAck], current tcb: {tcb:?}");
        Self::send_ack_to_tun(id, tcb.sequence_number, tcb.acknowledgment_number, ip_packet_output_sender, None).await?;
        tcb.status = TcpConnectionStatus::LastAck;
        Self::send_fin_ack_to_tun(id, tcb.sequence_number, tcb.acknowledgment_number, ip_packet_output_sender).await?;
        Ok(())
    }

    async fn start_dst_relay(
        id: TcpConnectionId, ip_packet_output_sender: Sender<Vec<u8>>, mut dst_read: OwnedReadHalf, tcb: Arc<Mutex<TransmissionControlBlock>>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let mut tcb = tcb.lock().await;
                debug!(
                    "<<<< Tcp connection [{id}] relay destination data to tun, before current read: sequence_number={}, acknowledgment_number={}",
                    tcb.sequence_number, tcb.acknowledgment_number,
                );
                let mut dst_data = [0u8; MAX_TCP_PACKET_PAYLOAD_SIZE];
                let size = match dst_read.read(&mut dst_data).await {
                    Ok(0) => {
                        // Close the connection activally when read destination complete
                        debug!("<<<< Tcp connection [{id}] read destination data complete send fin to tun, current tcb:{tcb:?}");
                        if let Err(e) = Self::send_fin_ack_to_tun(id, tcb.sequence_number, tcb.acknowledgment_number, &ip_packet_output_sender).await {
                            error!("<<<< Tcp connection [{id}] fail to send fin ack packet to tun because of error: {e:?}");
                            return;
                        };
                        tcb.status = TcpConnectionStatus::FinWait1;
                        tcb.sequence_number += 1;
                        return;
                    },
                    Ok(size) => size,
                    Err(e) => {
                        error!("<<<< Tcp connection [{id}] fail to read destination data because of error: {e:?}");
                        return;
                    },
                };
                let dst_data = &dst_data[..size];
                tcb.sequence_number += size as u32;
                if let Err(e) = Self::send_ack_to_tun(id, tcb.sequence_number, tcb.acknowledgment_number, &ip_packet_output_sender, Some(dst_data)).await {
                    error!("<<<< Tcp connection [{id}] fail to generate ip packet write to tun device because of error: {e:?}");
                    return;
                };
                debug!(
                    "<<<< Tcp connection [{id}] success relay destination data to tun, payload size={}, sequence_number={}, acknowledgment_number={}:\n{}\n",
                    size,
                    tcb.sequence_number,
                    tcb.acknowledgment_number,
                    pretty_hex::pretty_hex(&dst_data)
                );
            }
        })
    }

    async fn send_ack_to_tun(
        id: TcpConnectionId, sequence_number: u32, acknowledgment_number: u32, ip_packet_output_sender: &Sender<Vec<u8>>, payload: Option<&[u8]>,
    ) -> Result<()> {
        let ip_packet = PacketBuilder::ipv4(id.dst_addr.octets(), id.src_addr.octets(), IP_PACKET_TTL)
            .tcp(id.dst_port, id.src_port, sequence_number, WINDOW_SIZE)
            .ack(acknowledgment_number);
        let mut ip_packet_bytes = if let Some(payload) = payload {
            Vec::with_capacity(ip_packet.size(payload.len()))
        } else {
            Vec::with_capacity(ip_packet.size(0))
        };

        let payload = if let Some(payload) = payload {
            payload
        } else {
            &[0u8; 0]
        };
        ip_packet.write(&mut ip_packet_bytes, payload)?;
        ip_packet_output_sender.send(ip_packet_bytes).await?;
        debug!(
            "<<<< Tcp connection [{id}] send ack to device, payload size={}, sequence_number={sequence_number}, acknowledgment_number={acknowledgment_number}",
            payload.len()
        );
        Ok(())
    }

    async fn send_fin_ack_to_tun(
        id: TcpConnectionId, sequence_number: u32, acknowledgment_number: u32, ip_packet_output_sender: &Sender<Vec<u8>>,
    ) -> Result<()> {
        let ip_packet = PacketBuilder::ipv4(id.dst_addr.octets(), id.src_addr.octets(), IP_PACKET_TTL)
            .tcp(id.dst_port, id.src_port, acknowledgment_number, WINDOW_SIZE)
            .fin()
            .ack(acknowledgment_number);
        let mut ip_packet_bytes = Vec::with_capacity(ip_packet.size(0));
        ip_packet.write(&mut ip_packet_bytes, &[0u8; 0])?;
        ip_packet_output_sender.send(ip_packet_bytes).await?;
        debug!("<<<< Tcp connection [{id}] send fin ack to device, sequence_number={sequence_number}, acknowledgment_number={acknowledgment_number}",);
        Ok(())
    }

    async fn send_syn_ack_to_tun(
        id: TcpConnectionId, sequence_number: u32, acknowledgment_number: u32, ip_packet_output_sender: &Sender<Vec<u8>>,
    ) -> Result<()> {
        let ip_packet = PacketBuilder::ipv4(id.dst_addr.octets(), id.src_addr.octets(), IP_PACKET_TTL)
            .tcp(id.dst_port, id.src_port, sequence_number, WINDOW_SIZE)
            .syn()
            .ack(acknowledgment_number);

        let mut ip_packet_bytes = Vec::with_capacity(ip_packet.size(0));
        ip_packet.write(&mut ip_packet_bytes, &[0u8; 0])?;
        ip_packet_output_sender.send(ip_packet_bytes).await?;
        debug!("<<<< Tcp connection [{id}] send syn ack to device, sequence_number={sequence_number}, acknowledgment_number={acknowledgment_number}",);
        Ok(())
    }

    async fn send_rst_ack_to_tun(
        id: TcpConnectionId, sequence_number: u32, acknowledgment_number: u32, ip_packet_output_sender: &Sender<Vec<u8>>,
    ) -> Result<()> {
        let ip_packet = PacketBuilder::ipv4(id.dst_addr.octets(), id.src_addr.octets(), IP_PACKET_TTL)
            .tcp(id.dst_port, id.src_port, sequence_number, WINDOW_SIZE)
            .rst()
            .ack(acknowledgment_number);

        let mut ip_packet_bytes = Vec::with_capacity(ip_packet.size(0));
        ip_packet.write(&mut ip_packet_bytes, &[0u8; 0])?;
        ip_packet_output_sender.send(ip_packet_bytes).await?;
        debug!("<<<< Tcp connection [{id}] send rst ack to device, sequence_number={sequence_number}, acknowledgment_number={acknowledgment_number}",);
        Ok(())
    }
}
