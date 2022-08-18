package com.ppaass.agent.service.handler;

import android.util.Log;
import com.ppaass.agent.protocol.general.icmp.IcmpPacket;
import com.ppaass.agent.protocol.general.ip.IIpHeader;
import com.ppaass.agent.protocol.general.ip.IpPacket;
import com.ppaass.agent.protocol.general.ip.IpPacketReader;
import com.ppaass.agent.protocol.general.ip.IpV4Header;
import com.ppaass.agent.protocol.general.tcp.TcpPacket;
import com.ppaass.agent.protocol.general.udp.UdpPacket;
import com.ppaass.agent.service.PpaassVpnService;
import com.ppaass.agent.service.handler.icmp.IpV4IcmpPacketHandler;
import com.ppaass.agent.service.handler.tcp.IpV4TcpConnectionHandler;
import com.ppaass.agent.service.handler.udp.IpV4UdpPacketHandler;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.concurrent.Executors;

public class IpPacketHandler {
    private final FileChannel rawDeviceInputChannel;
    private final int readBufferSize;
    private final IpV4TcpConnectionHandler ipV4TcpConnectionHandler;
    private final IpV4UdpPacketHandler ipV4UdpPacketHandler;
    private final IpV4IcmpPacketHandler ipV4IcmpPacketHandler;
    private final PpaassVpnService vpnService;

    public IpPacketHandler(FileInputStream rawDeviceInputStream, FileOutputStream rawDeviceOutputStream,
                           int readBufferSize,
                           PpaassVpnService vpnService) throws Exception {
        this.rawDeviceInputChannel = rawDeviceInputStream.getChannel();
        this.readBufferSize = readBufferSize;
        this.vpnService = vpnService;
        this.ipV4TcpConnectionHandler = new IpV4TcpConnectionHandler(rawDeviceOutputStream, vpnService);
        this.ipV4UdpPacketHandler = new IpV4UdpPacketHandler(rawDeviceOutputStream, vpnService);
        this.ipV4IcmpPacketHandler = new IpV4IcmpPacketHandler();
    }

    public void start() {
        Executors.newWorkStealingPool(8).execute(() -> {
            while (IpPacketHandler.this.vpnService.isRunning()) {
                try {
                    IpPacket ipPacket = IpPacketHandler.this.read();
                    if (ipPacket == null) {
                        Thread.yield();
                        continue;
                    }
                    IpPacketHandler.this.handle(ipPacket);
                } catch (Exception e) {
                    Log.e(IpPacketHandler.class.getName(),
                            "Fail to read ip packet from raw input stream because of exception.", e);
                }
            }
        });
    }

    public void handle(IpPacket element) throws Exception {
        IIpHeader ipHeader = element.getHeader();
        switch (ipHeader.getVersion()) {
            case V4: {
                IpV4Header ipV4Header = (IpV4Header) ipHeader;
                switch (ipV4Header.getProtocol()) {
                    case TCP: {
                        TcpPacket tcpPacket = (TcpPacket) element.getData();
                        this.ipV4TcpConnectionHandler.handle(tcpPacket, ipV4Header);
                        break;
                    }
                    case UDP: {
                        UdpPacket udpPacket = (UdpPacket) element.getData();
                        this.ipV4UdpPacketHandler.handle(udpPacket, ipV4Header);
                        break;
                    }
                    case ICMP: {
                        IcmpPacket<?> icmpPacket = (IcmpPacket<?>) element.getData();
                        this.ipV4IcmpPacketHandler.handle(icmpPacket, ipV4Header);
                        break;
                    }
                    default: {
                        Log.e(IpPacketHandler.class.getName(),
                                "Ignore unsupported protocol: " + ipV4Header.getProtocol());
                        break;
                    }
                }
                break;
            }
            case V6: {
//                Log.e(IpPacketHandler.class.getName(), "Ignore IpV6 packet because of not support");
                break;
            }
            default: {
                throw new UnsupportedOperationException("Unsupported ip version.");
            }
        }
    }

    private IpPacket read() {
        ByteBuffer deviceInputBuffer = ByteBuffer.allocateDirect(this.readBufferSize);
        try {
            int size = this.rawDeviceInputChannel.read(deviceInputBuffer);
            if (size <= 0) {
                Log.d(IpPacketHandler.class.getName(),
                        "Nothing to read from raw input stream because of read size: " + size);
                return null;
            }
            deviceInputBuffer.flip();
            byte[] buffer = new byte[deviceInputBuffer.remaining()];
            deviceInputBuffer.get(buffer);
            return IpPacketReader.INSTANCE.parse(buffer);
        } catch (Exception e) {
            Log.e(IpPacketHandler.class.getName(),
                    "Fail to read ip packet from raw input stream because of exception.", e);
            throw new RuntimeException(e);
        } finally {
            deviceInputBuffer.clear();
        }
    }
}
