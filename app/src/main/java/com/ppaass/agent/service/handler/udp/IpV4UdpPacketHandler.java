package com.ppaass.agent.service.handler.udp;

import android.net.VpnService;
import android.util.Log;
import androidx.annotation.NonNull;
import com.ppaass.agent.protocol.general.ip.*;
import com.ppaass.agent.protocol.general.udp.UdpPacket;
import com.ppaass.agent.protocol.message.*;
import com.ppaass.agent.service.IVpnConst;
import com.ppaass.agent.service.PpaassVpnTcpChannelFactory;
import com.ppaass.agent.service.handler.IUdpIpPacketWriter;
import com.ppaass.agent.service.handler.PpaassMessageDecoder;
import com.ppaass.agent.service.handler.PpaassMessageEncoder;
import com.ppaass.agent.service.handler.PpaassMessageUtil;
import com.ppaass.agent.util.UUIDUtil;
import io.netty.bootstrap.Bootstrap;
import io.netty.buffer.Unpooled;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.embedded.EmbeddedChannel;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.DatagramPacket;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.codec.dns.DatagramDnsQueryDecoder;
import io.netty.handler.codec.dns.DnsQuery;
import io.netty.util.concurrent.DefaultPromise;
import io.netty.util.concurrent.Promise;

import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class IpV4UdpPacketHandler implements IUdpIpPacketWriter {
    private final FileOutputStream rawDeviceOutputStream;
    private final VpnService vpnService;
    private final ExecutorService udpThreadPool;
    private Channel proxyChannel;

    public IpV4UdpPacketHandler(FileOutputStream rawDeviceOutputStream, VpnService vpnService)
            throws Exception {
        this.rawDeviceOutputStream = rawDeviceOutputStream;
        this.vpnService = vpnService;
        this.udpThreadPool = Executors.newWorkStealingPool(32);
        this.proxyChannel = this.prepareUdpChannel();
    }

    private Channel prepareUdpChannel() throws Exception {
        InetSocketAddress proxyAddress =
                new InetSocketAddress(InetAddress.getByName(IVpnConst.PPAASS_PROXY_IP), IVpnConst.PPAASS_PROXY_PORT);
        NioEventLoopGroup udpNioEventLoopGroup = new NioEventLoopGroup(3);
        Promise<Channel> udpAssociatePromise = new DefaultPromise<>(udpNioEventLoopGroup.next());
        Bootstrap udpBootstrap = new Bootstrap();
        udpBootstrap.group(udpNioEventLoopGroup);
        udpBootstrap.channelFactory(new PpaassVpnTcpChannelFactory(this.vpnService));
        udpBootstrap.option(ChannelOption.CONNECT_TIMEOUT_MILLIS, 120 * 1000);
        udpBootstrap.option(ChannelOption.SO_TIMEOUT, 120 * 1000);
        udpBootstrap.option(ChannelOption.SO_KEEPALIVE, true);
        udpBootstrap.option(ChannelOption.AUTO_READ, true);
        udpBootstrap.option(ChannelOption.AUTO_CLOSE, false);
        udpBootstrap.option(ChannelOption.TCP_NODELAY, true);
        udpBootstrap.option(ChannelOption.SO_REUSEADDR, true);
        udpBootstrap.option(ChannelOption.TCP_FASTOPEN, Integer.MAX_VALUE);
        udpBootstrap.handler(new ChannelInitializer<NioSocketChannel>() {
            @Override
            protected void initChannel(@NonNull NioSocketChannel ch) {
                ch.pipeline().addLast(new PpaassMessageDecoder());
                ch.pipeline()
                        .addLast(new UdpProxyMessageHandler(IpV4UdpPacketHandler.this, udpAssociatePromise));
                ch.pipeline().addLast(new PpaassMessageEncoder(false));
            }
        });
        udpBootstrap.connect(proxyAddress).sync();
        return udpAssociatePromise.get(120, TimeUnit.SECONDS);
    }

    private void logDnsQuestion(UdpPacket udpPacket, IpV4Header ipHeader) {
        try {
            InetSocketAddress udpDestAddress =
                    new InetSocketAddress(InetAddress.getByAddress(ipHeader.getDestinationAddress()),
                            udpPacket.getHeader().getDestinationPort());
            InetSocketAddress udpSourceAddress =
                    new InetSocketAddress(InetAddress.getByAddress(ipHeader.getSourceAddress()),
                            udpPacket.getHeader().getSourcePort());
            DatagramPacket dnsPacket =
                    new DatagramPacket(Unpooled.wrappedBuffer(udpPacket.getData()), udpDestAddress, udpSourceAddress);
            EmbeddedChannel logChannel = new EmbeddedChannel();
            logChannel.pipeline().addLast(new DatagramDnsQueryDecoder());
            logChannel.writeInbound(dnsPacket);
            DnsQuery dnsQuery = logChannel.readInbound();
            Log.v(IpV4UdpPacketHandler.class.getName(), "---->>>> DNS Query: " + dnsQuery);
        } catch (Exception e) {
            Log.e(IpV4UdpPacketHandler.class.getName(), "---->>>> Error happen when logging DNS Query.", e);
        }
    }

    public void handle(UdpPacket udpPacket, IpV4Header ipV4Header) throws InterruptedException {
        this.udpThreadPool.submit(() -> {
            try {
                NetAddress sourceAddress = new NetAddress();
                sourceAddress.setHost(ipV4Header.getSourceAddress());
                sourceAddress.setPort(udpPacket.getHeader().getSourcePort());
                sourceAddress.setType(NetAddressType.IpV4);
                NetAddress targetAddress = new NetAddress();
                targetAddress.setType(NetAddressType.IpV4);
                targetAddress.setHost(ipV4Header.getDestinationAddress());
                targetAddress.setPort(udpPacket.getHeader().getDestinationPort());
                Message udpDataMessage = new Message();
                udpDataMessage.setId(UUIDUtil.INSTANCE.generateUuid());
                udpDataMessage.setUserToken(IVpnConst.PPAASS_USER_TOKEN);
                udpDataMessage.setPayloadEncryptionType(PayloadEncryptionType.Aes);
                udpDataMessage.setPayloadEncryptionToken(UUIDUtil.INSTANCE.generateUuidInBytes());
                AgentMessagePayload udpDataMessagePayload = new AgentMessagePayload();
                udpDataMessagePayload.setPayloadType(AgentMessagePayloadType.UdpData);
                udpDataMessagePayload.setSourceAddress(sourceAddress);
                udpDataMessagePayload.setTargetAddress(targetAddress);
                udpDataMessagePayload.setData(udpPacket.getData());
                udpDataMessage.setPayload(
                        PpaassMessageUtil.INSTANCE.generateAgentMessagePayloadBytes(
                                udpDataMessagePayload));
                this.logDnsQuestion(udpPacket, ipV4Header);
                if (!this.proxyChannel.isActive()) {
                    this.proxyChannel = this.prepareUdpChannel();
                }
                this.proxyChannel.writeAndFlush(udpDataMessage);
                Log.d(IpV4UdpPacketHandler.class.getName(),
                        "---->>>> Send udp packet to remote: " + udpPacket + ", ip header: " + ipV4Header);
            } catch (Exception e) {
                Log.e(IpV4UdpPacketHandler.class.getName(),
                        "Ip v4 udp handler have exception.", e);
            }
        });
    }

    @Override
    public void writeToDevice(short udpIpPacketId, UdpPacket udpPacket, byte[] sourceHost, byte[] destinationHost,
                              int udpResponseDataOffset)
            throws IOException {
        IpPacketBuilder ipPacketBuilder = new IpPacketBuilder();
        ipPacketBuilder.data(udpPacket);
        IpV4HeaderBuilder ipV4HeaderBuilder = new IpV4HeaderBuilder();
        ipV4HeaderBuilder.destinationAddress(destinationHost);
        ipV4HeaderBuilder.sourceAddress(sourceHost);
        ipV4HeaderBuilder.protocol(IpDataProtocol.UDP);
        ipV4HeaderBuilder.identification(udpIpPacketId);
        ipV4HeaderBuilder.fragmentOffset(udpResponseDataOffset);
        ipPacketBuilder.header(ipV4HeaderBuilder.build());
        IpPacket ipPacket = ipPacketBuilder.build();
        Log.v(IpV4UdpPacketHandler.class.getName(), "<<<<<<<< Write udp ip packet to device: " + ipPacket);
        ByteBuffer ipPacketBytes = IpPacketWriter.INSTANCE.write(ipPacket);
        byte[] bytesWriteToDevice = new byte[ipPacketBytes.remaining()];
        ipPacketBytes.get(bytesWriteToDevice);
        ipPacketBytes.clear();
        this.rawDeviceOutputStream.write(bytesWriteToDevice);
        this.rawDeviceOutputStream.flush();
    }
}
