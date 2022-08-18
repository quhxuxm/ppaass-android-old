package com.ppaass.agent.service.handler.tcp;

import android.net.VpnService;
import android.util.Log;
import com.ppaass.agent.protocol.general.ip.*;
import com.ppaass.agent.protocol.general.tcp.*;
import com.ppaass.agent.service.IVpnConst;
import com.ppaass.agent.service.handler.TcpIpPacketWriter;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

public class IpV4TcpConnectionHandler implements TcpIpPacketWriter, ITcpConnectionManager {
    private static final Random RANDOM = new Random();
    private static final AtomicInteger TIMESTAMP = new AtomicInteger();
    private final FileOutputStream rawDeviceOutputStream;
    private final Map<TcpConnectionRepositoryKey, TcpConnectionWrapper> connectionRepository;
    private final VpnService vpnService;
    private final ExecutorService connectionThreadPool;
    private final AtomicInteger ipIdentifier;

    private static class TcpConnectionWrapper {
        TcpConnection connection;
        Future<?> connectionTask;
    }

    public IpV4TcpConnectionHandler(FileOutputStream rawDeviceOutputStream, VpnService vpnService) {
        this.rawDeviceOutputStream = rawDeviceOutputStream;
        this.vpnService = vpnService;
        this.connectionRepository = new ConcurrentHashMap<>();
        this.connectionThreadPool = Executors.newWorkStealingPool(256);
        this.ipIdentifier = new AtomicInteger(RANDOM.nextInt(Short.MAX_VALUE * 2 + 2));
        Executors.newSingleThreadScheduledExecutor().scheduleAtFixedRate(() -> {
            this.connectionRepository.forEach((tcpConnectionRepositoryKey, tcpConnectionWrapper) -> {
                TcpConnection tcpConnection = tcpConnectionWrapper.connection;
                Future<?> tcpConnectionTask = tcpConnectionWrapper.connectionTask;
                long connectionIdleTime = tcpConnection.getLatestActiveTime() - System.currentTimeMillis();
                if (connectionIdleTime > 1000 * 120 && (tcpConnection.getStatus() == TcpConnectionStatus.LISTEN ||
                        tcpConnection.getStatus() == TcpConnectionStatus.CLOSED)) {
                    tcpConnectionTask.cancel(true);
                    this.connectionRepository.remove(tcpConnectionRepositoryKey);
                }
            });
        }, 0, 60, TimeUnit.SECONDS);
    }

    private TcpConnectionWrapper prepareTcpConnection(TcpConnectionRepositoryKey repositoryKey, TcpPacket tcpPacket) {
        synchronized (this.connectionRepository) {
            TcpConnectionWrapper result = this.connectionRepository.get(repositoryKey);
            if (result != null) {
                return result;
            }
            result = new TcpConnectionWrapper();
            result.connection = new TcpConnection(repositoryKey, this,
                    this,
                    this.vpnService);
            this.connectionRepository.put(repositoryKey, result);
            result.connectionTask = this.connectionThreadPool.submit(result.connection);
            Log.d(IpV4TcpConnectionHandler.class.getName(),
                    ">>>>>>>> Create tcp connection: " + result + ", tcp packet: " + tcpPacket +
                            ", connection repository size: " + this.connectionRepository.size() +
                            ", connection thread pool: " + this.connectionThreadPool);
            return result;
        }
    }

    private int generateChecksumToVerify(TcpPacket tcpPacket, IpV4Header ipV4Header) {
        ByteBuffer tcpPacketBuf = TcpPacketWriter.INSTANCE.write(tcpPacket, ipV4Header);
        byte[] tcpPacketBytes = new byte[tcpPacketBuf.remaining()];
        tcpPacketBuf.get(tcpPacketBytes);
        TcpPacket tcpPacketToVerify = TcpPacketReader.INSTANCE.parse(tcpPacketBytes);
        return tcpPacketToVerify.getHeader().getChecksum();
    }

    public void handle(TcpPacket tcpPacket, IpV4Header ipV4Header) throws Exception {
        int generatedChecksumToVerify = this.generateChecksumToVerify(tcpPacket, ipV4Header);
        if (generatedChecksumToVerify != tcpPacket.getHeader().getChecksum()) {
            Log.e(IpV4TcpConnectionHandler.class.getName(),
                    ">>>>>>>> Fail to verify checksum for tcp packet: " + tcpPacket +
                            ", ip header: " +
                            ipV4Header + ", generated check sum: " + generatedChecksumToVerify +
                            ", incoming checksum: " + tcpPacket.getHeader().getChecksum());
            return;
        }
        TcpHeader tcpHeader = tcpPacket.getHeader();
        int sourcePort = tcpHeader.getSourcePort();
        int destinationPort = tcpHeader.getDestinationPort();
        byte[] sourceAddress = ipV4Header.getSourceAddress();
        byte[] destinationAddress = ipV4Header.getDestinationAddress();
        TcpConnectionRepositoryKey tcpConnectionRepositoryKey =
                new TcpConnectionRepositoryKey(sourcePort, destinationPort, sourceAddress, destinationAddress);
        TcpConnectionWrapper tcpConnectionWrapper = this.prepareTcpConnection(tcpConnectionRepositoryKey, tcpPacket);
        TcpConnection tcpConnection = tcpConnectionWrapper.connection;
        tcpConnection.onDeviceInbound(tcpPacket);
        Log.v(IpV4TcpConnectionHandler.class.getName(),
                ">>>>>>>> Do inbound for tcp connection: " + tcpConnection + ", incoming tcp packet: " + tcpPacket +
                        ", ip header: " +
                        ipV4Header + ", tcp connection repository size: " +
                        this.connectionRepository.size());
    }

    @Override
    public void closeConnection(TcpConnectionRepositoryKey key) {
        synchronized (this) {
            TcpConnectionWrapper tcpConnectionWrapper = this.connectionRepository.remove(key);
            if (tcpConnectionWrapper == null) {
                return;
            }
            tcpConnectionWrapper.connectionTask.cancel(true);
        }
    }

    public void writeSyncAckToDevice(TcpConnection connection, long sequenceNumber, long acknowledgementNumber) {
        TcpPacketBuilder tcpPacketBuilder = new TcpPacketBuilder();
        tcpPacketBuilder.ack(true);
        tcpPacketBuilder.syn(true);
        tcpPacketBuilder.window(IVpnConst.TCP_WINDOW);
        ByteBuffer mssByteBuffer = ByteBuffer.allocate(2);
        mssByteBuffer.putShort((short) (IVpnConst.TCP_MSS & 0xFFFF));
        tcpPacketBuilder.addOption(new TcpHeaderOption(TcpHeaderOption.Kind.MSS, mssByteBuffer.array()));
        TcpPacket tcpPacket =
                this.buildCommonTcpPacket(tcpPacketBuilder, connection, sequenceNumber, acknowledgementNumber);
        try {
            this.write(connection, tcpPacket);
        } catch (IOException e) {
            Log.e(TcpConnection.class.getName(),
                    "Fail to write sync ack tcp packet to device outbound queue because of error.", e);
        }
    }

    public void writeAckToDevice(byte[] ackData, TcpConnection connection, long sequenceNumber,
                                 long acknowledgementNumber) {
        TcpPacketBuilder tcpPacketBuilder = new TcpPacketBuilder();
        tcpPacketBuilder.ack(true);
        tcpPacketBuilder.window(IVpnConst.TCP_WINDOW);
        tcpPacketBuilder.data(ackData);
        TcpPacket tcpPacket =
                this.buildCommonTcpPacket(tcpPacketBuilder, connection, sequenceNumber, acknowledgementNumber);
        try {
            this.write(connection, tcpPacket);
        } catch (IOException e) {
            Log.e(TcpConnection.class.getName(),
                    "Fail to write ack tcp packet to device outbound queue because of error.", e);
        }
    }

    public void writeRstAckToDevice(TcpConnection connection, long sequenceNumber,
                                    long acknowledgementNumber) {
        TcpPacketBuilder tcpPacketBuilder = new TcpPacketBuilder();
        tcpPacketBuilder.ack(true);
        tcpPacketBuilder.rst(true);
        tcpPacketBuilder.window(IVpnConst.TCP_WINDOW);
        TcpPacket tcpPacket =
                this.buildCommonTcpPacket(tcpPacketBuilder, connection, sequenceNumber, acknowledgementNumber);
        try {
            this.write(connection, tcpPacket);
        } catch (IOException e) {
            Log.e(TcpConnection.class.getName(),
                    "Fail to write rst tcp packet to device outbound queue because of error.", e);
        }
    }

    public void writeRstToDevice(TcpConnection connection, long sequenceNumber,
                                 long acknowledgementNumber) {
        TcpPacketBuilder tcpPacketBuilder = new TcpPacketBuilder();
        tcpPacketBuilder.rst(true);
        tcpPacketBuilder.window(IVpnConst.TCP_WINDOW);
        TcpPacket tcpPacket =
                this.buildCommonTcpPacket(tcpPacketBuilder, connection, sequenceNumber, acknowledgementNumber);
        try {
            this.write(connection, tcpPacket);
        } catch (IOException e) {
            Log.e(TcpConnection.class.getName(),
                    "Fail to write rst tcp packet to device outbound queue because of error.", e);
        }
    }

    public void writeFinAckToDevice(TcpConnection connection, long sequenceNumber,
                                    long acknowledgementNumber) {
        TcpPacketBuilder tcpPacketBuilder = new TcpPacketBuilder();
        tcpPacketBuilder.ack(true);
        tcpPacketBuilder.fin(true);
        tcpPacketBuilder.window(IVpnConst.TCP_WINDOW);
        TcpPacket tcpPacket =
                this.buildCommonTcpPacket(tcpPacketBuilder, connection, sequenceNumber, acknowledgementNumber);
        try {
            this.write(connection, tcpPacket);
        } catch (IOException e) {
            Log.e(TcpConnection.class.getName(),
                    "Fail to write fin ack tcp packet to device outbound queue because of error.", e);
        }
    }

    public void writeFinToDevice(TcpConnection connection, long sequenceNumber,
                                 long acknowledgementNumber) {
        TcpPacketBuilder tcpPacketBuilder = new TcpPacketBuilder();
        tcpPacketBuilder.fin(true);
        tcpPacketBuilder.window(IVpnConst.TCP_WINDOW);
        TcpPacket tcpPacket =
                this.buildCommonTcpPacket(tcpPacketBuilder, connection, sequenceNumber, acknowledgementNumber);
        try {
            this.write(connection, tcpPacket);
        } catch (IOException e) {
            Log.e(TcpConnection.class.getName(),
                    "Fail to write fin tcp packet to device outbound queue because of error.", e);
        }
    }

    private TcpPacket buildCommonTcpPacket(TcpPacketBuilder tcpPacketBuilder, TcpConnection connection,
                                           long sequenceNumber,
                                           long acknowledgementNumber) {
        tcpPacketBuilder.destinationPort(connection.getRepositoryKey().getSourcePort());
        tcpPacketBuilder.sourcePort(connection.getRepositoryKey().getDestinationPort());
        tcpPacketBuilder.sequenceNumber(sequenceNumber);
        tcpPacketBuilder.acknowledgementNumber(acknowledgementNumber);
        ByteBuffer mssBuffer = ByteBuffer.allocateDirect(2);
        mssBuffer.putShort((short) (IVpnConst.TCP_MSS & 0xFFFF));
        mssBuffer.flip();
        byte[] mssBytes = new byte[2];
        mssBuffer.get(mssBytes);
        tcpPacketBuilder.addOption(new TcpHeaderOption(TcpHeaderOption.Kind.MSS, mssBytes));
        int timestamp = TIMESTAMP.getAndIncrement();
        ByteBuffer timestampBuffer = ByteBuffer.allocateDirect(4);
        timestampBuffer.putInt(timestamp);
        timestampBuffer.flip();
        byte[] timestampBytes = new byte[4];
        timestampBuffer.get(timestampBytes);
        tcpPacketBuilder.addOption(new TcpHeaderOption(TcpHeaderOption.Kind.TSPOT, timestampBytes));
        return tcpPacketBuilder.build();
    }

    private void write(TcpConnection tcpConnection, TcpPacket tcpPacket) throws IOException {
        IpPacketBuilder ipPacketBuilder = new IpPacketBuilder();
        IpV4HeaderBuilder ipV4HeaderBuilder = new IpV4HeaderBuilder();
        ipV4HeaderBuilder.identification(this.ipIdentifier.incrementAndGet());
        ipV4HeaderBuilder.destinationAddress(tcpConnection.getRepositoryKey().getSourceAddress());
        ipV4HeaderBuilder.sourceAddress(tcpConnection.getRepositoryKey().getDestinationAddress());
        ipV4HeaderBuilder.protocol(IpDataProtocol.TCP);
        ipV4HeaderBuilder.ttl(64);
        ipV4HeaderBuilder.flags(new IpFlags(false, false));
        ipPacketBuilder.header(ipV4HeaderBuilder.build());
        ipPacketBuilder.data(tcpPacket);
        IpPacket ipPacket = ipPacketBuilder.build();
        ByteBuffer ipPacketBytes = IpPacketWriter.INSTANCE.write(ipPacket);
        Log.v(IpV4TcpConnectionHandler.class.getName(),
                "<<<<<<<< Write ip packet to device, current connection:  " + tcpConnection +
                        ", output ip packet: " + ipPacket);
        byte[] bytesWriteToDevice = new byte[ipPacketBytes.remaining()];
        ipPacketBytes.get(bytesWriteToDevice);
        ipPacketBytes.clear();
        this.rawDeviceOutputStream.write(bytesWriteToDevice);
        this.rawDeviceOutputStream.flush();
    }
}
