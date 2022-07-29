package com.ppaass.agent.service.handler.udp;

import android.net.VpnService;
import android.util.Log;
import com.ppaass.agent.protocol.general.ip.*;
import com.ppaass.agent.protocol.general.udp.UdpPacket;
import com.ppaass.agent.protocol.general.udp.UdpPacketBuilder;
import org.apache.commons.codec.binary.Hex;

import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.DatagramChannel;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class IpV4UdpPacketHandler {
    private final OutputStream rawDeviceOutputStream;
    private final int writeBufferSize;
    private final VpnService vpnService;
    private final ExecutorService udpThreadPool;

    public IpV4UdpPacketHandler(OutputStream rawDeviceOutputStream, int writeBufferSize, VpnService vpnService)
            throws Exception {
        this.rawDeviceOutputStream = rawDeviceOutputStream;
        this.writeBufferSize = writeBufferSize;
        this.vpnService = vpnService;
        this.udpThreadPool = Executors.newFixedThreadPool(32);
    }

    public void handle(UdpPacket udpPacket, IpV4Header ipV4Header) {
        this.udpThreadPool.execute(new Runnable() {
            @Override
            public void run() {
                Log.d(IpV4UdpPacketHandler.class.getName(), udpPacket.toString());
                try (DatagramChannel deviceToRemoteChannel = DatagramChannel.open()) {
                    if (!IpV4UdpPacketHandler.this.vpnService.protect(deviceToRemoteChannel.socket())) {
                        Log.e(IpV4UdpPacketHandler.class.getName(), "Fail to protect vpn udp socket");
                        throw new UnsupportedOperationException("Fail to protect vpn udp socket");
                    }
                    InetAddress destinationAddress = InetAddress.getByAddress(ipV4Header.getDestinationAddress());
                    int destinationPort = udpPacket.getHeader().getDestinationPort();
                    InetSocketAddress deviceToRemoteDestinationAddress =
                            new InetSocketAddress(destinationAddress, destinationPort);
                    deviceToRemoteChannel.socket().setSoTimeout(20000);
                    Log.d(IpV4UdpPacketHandler.class.getName(),
                            "Begin to send udp packet to remote: " + udpPacket + ", destination: " +
                                    deviceToRemoteDestinationAddress);
                    Log.d(IpV4UdpPacketHandler.class.getName(),
                            "Udp content going to send:\n\n" + Hex.encodeHexString(udpPacket.getData()) + "\n\n");
                    deviceToRemoteChannel.connect(deviceToRemoteDestinationAddress);
                    deviceToRemoteChannel.write(ByteBuffer.wrap(udpPacket.getData()));
                    ByteBuffer remoteToDeviceUdpPacketContent = ByteBuffer.allocateDirect(65535);
                    deviceToRemoteChannel.receive(remoteToDeviceUdpPacketContent);
                    deviceToRemoteChannel.disconnect();
                    UdpPacketBuilder remoteToDeviceUdpPacketBuilder = new UdpPacketBuilder();
                    remoteToDeviceUdpPacketContent.flip();
                    byte[] packetFromRemoteToDeviceContent = new byte[remoteToDeviceUdpPacketContent.remaining()];
                    remoteToDeviceUdpPacketContent.get(packetFromRemoteToDeviceContent);
                    remoteToDeviceUdpPacketBuilder.data(packetFromRemoteToDeviceContent);
                    remoteToDeviceUdpPacketBuilder.destinationPort(udpPacket.getHeader().getSourcePort());
                    remoteToDeviceUdpPacketBuilder.sourcePort(udpPacket.getHeader().getDestinationPort());
                    UdpPacket remoteToDeviceUdpPacket = remoteToDeviceUdpPacketBuilder.build();
                    Log.d(IpV4UdpPacketHandler.class.getName(),
                            "Success receive remote udp packet: " + remoteToDeviceUdpPacket);
                    Log.d(IpV4UdpPacketHandler.class.getName(),
                            "Udp content received:\n\n" + Hex.encodeHexString(packetFromRemoteToDeviceContent) +
                                    "\n\n");
                    IpPacketBuilder ipPacketBuilder = new IpPacketBuilder();
                    ipPacketBuilder.data(remoteToDeviceUdpPacket);
                    IpV4HeaderBuilder ipV4HeaderBuilder = new IpV4HeaderBuilder();
                    ipV4HeaderBuilder.destinationAddress(ipV4Header.getSourceAddress());
                    ipV4HeaderBuilder.sourceAddress(ipV4Header.getDestinationAddress());
                    ipV4HeaderBuilder.protocol(IpDataProtocol.UDP);
                    ipV4HeaderBuilder.identification((short) (Math.random() * 10000));
                    ipPacketBuilder.header(ipV4HeaderBuilder.build());
                    IpPacket ipPacket = ipPacketBuilder.build();
                    byte[] ipPacketBytes = IpPacketWriter.INSTANCE.write(ipPacket);
                    IpV4UdpPacketHandler.this.rawDeviceOutputStream.write(ipPacketBytes);
                    IpV4UdpPacketHandler.this.rawDeviceOutputStream.flush();
                } catch (Exception e) {
                    Log.e(IpV4UdpPacketHandler.class.getName(),
                            "Fail to handle udp packet because of exception, udp packet: " + udpPacket, e);
                }
            }
        });
    }
}
