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
use bytes::BufMut;
use etherparse::{PacketBuilder, TcpHeader};
use log::{debug, error, trace};

use rand::random;
use tokio::{
    io::AsyncReadExt,
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
    task::JoinHandle,
    time::timeout,
};
use tokio::{io::AsyncWriteExt, sync::Notify};

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
    tcp_packet_input_receiver: Receiver<(TcpHeader, Vec<u8>)>,
    ip_packet_output_sender: Sender<Vec<u8>>,
    tcp_packet_input_handle: TcpConnectionTcpPacketInputHandle,
    tcb: Arc<Mutex<TransmissionControlBlock>>,
    dst_read_notify: Arc<Notify>,
    dst_write_notify: Arc<Notify>,
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
            dst_read_notify: Default::default(),
            dst_write_notify: Default::default(),
        }
    }

    pub(crate) fn clone_input_handle(&self) -> TcpConnectionTcpPacketInputHandle {
        self.tcp_packet_input_handle.clone()
    }

    pub(crate) async fn process(&mut self) -> Result<()> {
        if let Err(e) = self.concrete_process().await {
            let tcb = self.tcb.lock().await;
            error!(
                "<<<< Tcp connection [{}] fail to process state machine because of error, {tcb:?}, error: {e:?}",
                self.id
            );
            Self::send_rst_ack_to_device(self.id, tcb.sequence_number, tcb.acknowledgment_number, &self.ip_packet_output_sender).await?;
            return Err(e);
        }
        Ok(())
    }

    async fn concrete_process(&mut self) -> Result<()> {
        loop {
            let (tcp_header, payload) = match self.tcp_packet_input_receiver.recv().await {
                Some(value) => value,
                None => {
                    debug!(">>>> Tcp connection [{}] complete to read device data.", self.id);
                    break;
                },
            };

            if tcp_header.rst {
                error!(">>>> Tcp connection [{}] receive rst packet.", self.id);
                return Err(anyhow!("Tcp connection [{}] receive rst packet.", self.id));
            }
            let tcp_connection_status = {
                let tcb = self.tcb.lock().await;
                debug!(
                    ">>>> Tcp connection [{}] receive: {tcp_header:?}, payload size={}, {}",
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
                    Self::on_syn_received(
                        self.id,
                        self.tcb.clone(),
                        &self.ip_packet_output_sender,
                        self.dst_read_notify.clone(),
                        self.dst_write_notify.clone(),
                        tcp_header,
                    )
                    .await?;

                    continue;
                },
                TcpConnectionStatus::Established => {
                    Self::on_established(
                        self.id,
                        self.tcb.clone(),
                        &self.ip_packet_output_sender,
                        self.dst_write_notify.clone(),
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
            error!(">>>> Tcp connection [{id}] fail to process [Listen] because of not a syn packet, {}", &tcb);
            return Err(anyhow!("Tcp connection [{id}] fail to process [Listen] because of not a syn packet, {}", &tcb));
        }

        let iss = random::<u32>();
        tcb.status = TcpConnectionStatus::SynReceived;
        tcb.sequence_number = iss;
        tcb.acknowledgment_number = tcp_header.sequence_number + 1;
        tcb.initial_sequence_number = iss;
        tcb.initial_acknowledgement_number = tcp_header.sequence_number + 1;
        tcb.tx_window_size = tcp_header.window_size;
        Self::send_syn_ack_to_device(id, tcb.sequence_number, tcb.acknowledgment_number, ip_packet_output_sender, tcb.rx_window_size).await?;
        debug!("<<<< Tcp connection [{id}] switch to [SynReceived], {}", &tcb);
        Ok(())
    }

    async fn on_syn_received(
        id: TcpConnectionId, tbc: Arc<Mutex<TransmissionControlBlock>>, ip_packet_output_sender: &Sender<Vec<u8>>, dst_read_notify: Arc<Notify>,
        dst_write_notify: Arc<Notify>, tcp_header: TcpHeader,
    ) -> Result<()> {
        if tcp_header.syn {
            error!(">>>> Tcp connection [{id}] fail to process [SynReceived] because of incoming packet is a syn packet",);
            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [SynReceived] because of incoming packet is a syn packet",
            ));
        }
        if !tcp_header.ack {
            // In SynReceived status, connection should receive a ack.
            error!(">>>> Tcp connection [{id}] fail to process [SynReceived] because of incoming packet is not a ack packet",);
            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [SynReceived] because of incoming packet is not a ack packet",
            ));
        }
        // Process the connection when the connection in SynReceived status

        let mut tcb = tbc.lock().await;
        if tcp_header.acknowledgment_number != tcb.sequence_number + 1 {
            error!(
                ">>>> Tcp connection [{id}] fail to process [SynReceived] because of un expected sequence number, {}",
                &tcb
            );
            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [SynReceived] because of un expected sequence number, {}",
                &tcb
            ));
        }

        let dst_socket = tokio::net::TcpSocket::new_v4()?;
        let dst_socket_raw_fd = dst_socket.as_raw_fd();
        protect_socket(dst_socket_raw_fd)?;
        let dst_socket_addr = SocketAddr::new(IpAddr::V4(id.dst_addr), id.dst_port);
        let dst_tcp_stream = timeout(Duration::from_secs(CONNECT_TO_DST_TIMEOUT), dst_socket.connect(dst_socket_addr)).await??;

        debug!(">>>> Tcp connection [{}] connect to destination success, {}", id, &tcb);
        let (dst_read, dst_write) = dst_tcp_stream.into_split();

        Self::start_dst_relay(
            id,
            ip_packet_output_sender.clone(),
            dst_read,
            dst_write,
            tbc.clone(),
            dst_read_notify,
            dst_write_notify,
        )
        .await;

        tcb.status = TcpConnectionStatus::Established;

        tcb.sequence_number += 1;
        tcb.acknowledgment_number = tcp_header.sequence_number;
        tcb.tx_window_size = tcp_header.window_size;

        debug!(">>>> Tcp connection [{id}] switch to [Established], {}", &tcb);
        Ok(())
    }

    async fn on_established(
        id: TcpConnectionId, tbc: Arc<Mutex<TransmissionControlBlock>>, ip_packet_output_sender: &Sender<Vec<u8>>, dst_write_notify: Arc<Notify>,
        tcp_header: TcpHeader, payload: Vec<u8>,
    ) -> Result<()> {
        // Process the connection when the connection in Established status
        let mut tcb = tbc.lock().await;

        if tcb.sequence_number < tcp_header.acknowledgment_number {
            error!(
                ">>>> Tcp connection [{id}] fail to process [Established] because of unexpected sequence number, {}",
                &tcb
            );
            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [Established] because of unexpected sequence number, {}",
                &tcb
            ));
        }

        if tcb.acknowledgment_number > tcp_header.sequence_number {
            error!(
                ">>>> Tcp connection [{id}] fail to process [Established] because of unexpected acknowledgment number, {}",
                &tcb
            );
            return Err(anyhow!(
                "Tcp connection [{id}] fail to process [Established] because of unexpected acknowledgment number, {}",
                &tcb
            ));
        }

        // Relay from device to destination.
        let device_data_length = payload.len() as u16;
        if device_data_length <= tcb.rx_window_size {
            tcb.rx_window.extend(&payload);
            tcb.rx_window_size -= device_data_length;
            Self::send_ack_to_device(
                id,
                tcb.sequence_number,
                tcp_header.sequence_number + device_data_length as u32,
                ip_packet_output_sender,
                None,
                tcb.rx_window_size,
            )
            .await?;
            tcb.acknowledgment_number = tcp_header.sequence_number + device_data_length as u32;
        } else {
            Self::send_ack_to_device(
                id,
                tcb.sequence_number,
                tcp_header.sequence_number,
                ip_packet_output_sender,
                None,
                tcb.rx_window_size,
            )
            .await?;
        }
        debug!(
            ">>>> Tcp connection [{id}] success relay device data [size={}] to destination, {}, device data:\n{}\n",
            device_data_length,
            &tcb,
            pretty_hex::pretty_hex(&payload)
        );
        dst_write_notify.notify_one();

        if tcp_header.fin {
            tcb.status = TcpConnectionStatus::CloseWait;

            debug!(
                ">>>> Tcp connection [{id}] in [Established] status, receive FIN, switch to [CloseWait], {}",
                &tcb
            );
            Self::send_ack_to_device(id, tcb.sequence_number, tcb.acknowledgment_number + 1, ip_packet_output_sender, None, 0).await?;
            tcb.acknowledgment_number += 1;
            tcb.status = TcpConnectionStatus::LastAck;
            debug!(">>>> Tcp connection [{id}] in [CloseWait] status, switch to [LastAck], {}", &tcb);
            Self::send_fin_ack_to_device(id, tcb.sequence_number, tcb.acknowledgment_number, ip_packet_output_sender, tcb.rx_window_size).await?;
            return Ok(());
        }
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
        Self::send_ack_to_device(id, tcb.sequence_number, tcp_header.sequence_number + 1, ip_packet_output_sender, None, 0).await?;
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
        Self::send_ack_to_device(id, tcb.sequence_number, tcb.acknowledgment_number, ip_packet_output_sender, None, 0).await?;
        debug!(">>>> Tcp connection [{id}] keep in [TimeWait], current tcb: {tcb:?}");
        Ok(())
    }

    async fn on_close_wait(
        id: TcpConnectionId, tbc: Arc<Mutex<TransmissionControlBlock>>, ip_packet_output_sender: &Sender<Vec<u8>>, tcp_header: TcpHeader,
    ) -> Result<()> {
        let mut tcb = tbc.lock().await;
        debug!(">>>> Tcp connection [{id}] in [CloseWait] status, switch to [LastAck], current tcb: {tcb:?}");
        Self::send_ack_to_device(id, tcb.sequence_number, tcb.acknowledgment_number, ip_packet_output_sender, None, 0).await?;
        tcb.status = TcpConnectionStatus::LastAck;
        Self::send_fin_ack_to_device(id, tcb.sequence_number, tcb.acknowledgment_number, ip_packet_output_sender, tcb.rx_window_size).await?;
        Ok(())
    }

    async fn start_dst_relay(
        id: TcpConnectionId, ip_packet_output_sender: Sender<Vec<u8>>, mut dst_read: OwnedReadHalf, mut dst_write: OwnedWriteHalf,
        tcb: Arc<Mutex<TransmissionControlBlock>>, dst_read_notify: Arc<Notify>, dst_write_notify: Arc<Notify>,
    ) -> (JoinHandle<()>, JoinHandle<()>) {
        let dst_write_task = {
            let tcb = tcb.clone();
            tokio::spawn(async move {
                loop {
                    dst_write_notify.notified().await;
                    let mut tcb = tcb.lock().await;
                    let rx_window_data_size = tcb.rx_window.len();
                    if let Err(e) = dst_write.write(&tcb.rx_window).await {
                        error!(">>>> Fail to write device data to destination because of error: {e:?}");
                        return;
                    };
                    if let Err(e) = dst_write.flush().await {
                        error!(">>>> Fail to flush device data to destination because of error: {e:?}");
                        return;
                    };
                    tcb.rx_window_size -= rx_window_data_size as u16;
                    tcb.rx_window.clear();
                }
            })
        };
        let dst_read_task = tokio::spawn(async move {
            loop {
                let mut tcb = tcb.lock().await;
                if tcb.tx_window_size == 0 {
                    dst_read_notify.notified().await;
                }
                let mut dst_data = vec![0u8; tcb.tx_window_size as usize];
                let size = match dst_read.read(&mut dst_data).await {
                    Ok(0) => {
                        // Close the connection activally when read destination complete
                        debug!("<<<< Tcp connection [{id}] read destination data complete, {tcb:?}");
                        // if let Err(e) = Self::send_fin_ack_to_tun(id, tcb.sequence_number, tcb.acknowledgment_number, &ip_packet_output_sender).await {
                        //     error!("<<<< Tcp connection [{id}] fail to send fin ack packet to tun because of error: {e:?}");
                        //     return;
                        // };
                        // tcb.status = TcpConnectionStatus::FinWait1;
                        // tcb.sequence_number += 1;
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
                if let Err(e) = Self::send_ack_to_device(
                    id,
                    tcb.sequence_number,
                    tcb.acknowledgment_number,
                    &ip_packet_output_sender,
                    Some(dst_data),
                    tcb.rx_window_size,
                )
                .await
                {
                    error!("<<<< Tcp connection [{id}] fail to generate ip packet write to tun device because of error: {e:?}");
                    return;
                };
                debug!(
                    "<<<< Tcp connection [{id}] success relay destination data to tun, payload size={},{}, destination payload:\n{}\n",
                    size,
                    &tcb,
                    pretty_hex::pretty_hex(&dst_data)
                );
            }
        });
        (dst_read_task, dst_write_task)
    }

    async fn send_ack_to_device(
        id: TcpConnectionId, sequence_number: u32, acknowledgment_number: u32, ip_packet_output_sender: &Sender<Vec<u8>>, payload: Option<&[u8]>,
        rx_window_size: u16,
    ) -> Result<()> {
        let ip_packet = PacketBuilder::ipv4(id.dst_addr.octets(), id.src_addr.octets(), IP_PACKET_TTL)
            .tcp(id.dst_port, id.src_port, sequence_number, rx_window_size)
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

    async fn send_fin_ack_to_device(
        id: TcpConnectionId, sequence_number: u32, acknowledgment_number: u32, ip_packet_output_sender: &Sender<Vec<u8>>, rx_window_size: u16,
    ) -> Result<()> {
        let ip_packet = PacketBuilder::ipv4(id.dst_addr.octets(), id.src_addr.octets(), IP_PACKET_TTL)
            .tcp(id.dst_port, id.src_port, acknowledgment_number, rx_window_size)
            .fin()
            .ack(acknowledgment_number);
        let mut ip_packet_bytes = Vec::with_capacity(ip_packet.size(0));
        ip_packet.write(&mut ip_packet_bytes, &[0u8; 0])?;
        ip_packet_output_sender.send(ip_packet_bytes).await?;
        debug!("<<<< Tcp connection [{id}] send fin ack to device, sequence_number={sequence_number}, acknowledgment_number={acknowledgment_number}",);
        Ok(())
    }

    async fn send_syn_ack_to_device(
        id: TcpConnectionId, sequence_number: u32, acknowledgment_number: u32, ip_packet_output_sender: &Sender<Vec<u8>>, rx_window_size: u16,
    ) -> Result<()> {
        let ip_packet = PacketBuilder::ipv4(id.dst_addr.octets(), id.src_addr.octets(), IP_PACKET_TTL)
            .tcp(id.dst_port, id.src_port, sequence_number, rx_window_size)
            .syn()
            .ack(acknowledgment_number);

        let mut ip_packet_bytes = Vec::with_capacity(ip_packet.size(0));
        ip_packet.write(&mut ip_packet_bytes, &[0u8; 0])?;
        ip_packet_output_sender.send(ip_packet_bytes).await?;
        debug!("<<<< Tcp connection [{id}] send syn ack to device, sequence_number={sequence_number}, acknowledgment_number={acknowledgment_number}",);
        Ok(())
    }

    async fn send_rst_ack_to_device(
        id: TcpConnectionId, sequence_number: u32, acknowledgment_number: u32, ip_packet_output_sender: &Sender<Vec<u8>>,
    ) -> Result<()> {
        let ip_packet = PacketBuilder::ipv4(id.dst_addr.octets(), id.src_addr.octets(), IP_PACKET_TTL)
            .tcp(id.dst_port, id.src_port, sequence_number, 0)
            .rst()
            .ack(acknowledgment_number);

        let mut ip_packet_bytes = Vec::with_capacity(ip_packet.size(0));
        ip_packet.write(&mut ip_packet_bytes, &[0u8; 0])?;
        ip_packet_output_sender.send(ip_packet_bytes).await?;
        debug!("<<<< Tcp connection [{id}] send rst ack to device, sequence_number={sequence_number}, acknowledgment_number={acknowledgment_number}",);
        Ok(())
    }
}
