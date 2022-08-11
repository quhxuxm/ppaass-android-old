package com.ppaass.agent.service.handler.tcp;

import android.util.Log;
import com.ppaass.agent.service.IVpnConst;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.SimpleChannelInboundHandler;
import io.netty.util.AttributeKey;

public class TcpConnectionRelayRemoteHandler extends SimpleChannelInboundHandler<ByteBuf> {
    public TcpConnectionRelayRemoteHandler() {
    }

    @Override
    public void channelActive(ChannelHandlerContext ctx) throws Exception {
        AttributeKey<TcpConnection> tcpConnectionKey = AttributeKey.valueOf(IVpnConst.TCP_CONNECTION);
        TcpConnection tcpConnection = ctx.channel().attr(tcpConnectionKey).get();
        if (tcpConnection == null) {
            ctx.close();
            return;
        }
        synchronized (tcpConnection) {
            if (tcpConnection.getStatus() == TcpConnectionStatus.CLOSED) {
                Log.d(TcpConnection.class.getName(),
                        "<<<<---- Tcp connection closed already, current connection:  " +
                                tcpConnection);
                ctx.close();
                return;
            }
            Log.d(TcpConnection.class.getName(),
                    "<<<<---- Tcp connection connected, begin to relay remote data to device, current connection:  " +
                            tcpConnection);
        }
    }

    @Override
    public void channelReadComplete(ChannelHandlerContext ctx) throws Exception {
        AttributeKey<TcpConnection> tcpConnectionKey = AttributeKey.valueOf(IVpnConst.TCP_CONNECTION);
        TcpConnection tcpConnection = ctx.channel().attr(tcpConnectionKey).get();
        if (tcpConnection == null) {
            ctx.close();
            return;
        }
        synchronized (tcpConnection) {
            if (tcpConnection.getStatus() == TcpConnectionStatus.CLOSED) {
                Log.d(TcpConnection.class.getName(),
                        "<<<<---- Tcp connection CLOSED already, current connection:  " +
                                tcpConnection);
                ctx.close();
                return;
            }
            if (tcpConnection.getStatus() == TcpConnectionStatus.CLOSED_WAIT) {
                tcpConnection.writeFinAckToDevice();
                tcpConnection.setStatus(TcpConnectionStatus.LAST_ACK);
                tcpConnection.setCurrentSequenceNumber(tcpConnection.getCurrentSequenceNumber() + 1);
                Log.d(TcpConnection.class.getName(),
                        "<<<<---- Move tcp connection from CLOSED_WAIT to  LAST_ACK, current connection:  " +
                                tcpConnection);
            }
        }
    }

    @Override
    protected void channelRead0(ChannelHandlerContext ctx, ByteBuf remoteDataBuf) throws Exception {
        AttributeKey<TcpConnection> tcpConnectionKey = AttributeKey.valueOf(IVpnConst.TCP_CONNECTION);
        TcpConnection tcpConnection = ctx.channel().attr(tcpConnectionKey).get();
        if (tcpConnection == null) {
            ctx.close();
            return;
        }
        synchronized (tcpConnection) {
            if (tcpConnection.getStatus() == TcpConnectionStatus.CLOSED) {
                Log.d(TcpConnection.class.getName(),
                        "<<<<---- Connection in closed status, stop relay remote data to device, current connection: " +
                                tcpConnection);
                ctx.close();
                return;
            }
            //Relay remote data to device and use mss as the transfer unit
            while (remoteDataBuf.isReadable()) {
                int mssDataLength = Math.min(IVpnConst.TCP_MSS, remoteDataBuf.readableBytes());
                byte[] mssData = new byte[mssDataLength];
                remoteDataBuf.readBytes(mssData);
                int windowSize = tcpConnection.getCurrentWindowSize();
                tcpConnection.writeAckToDevice(mssData, windowSize);
                // Data should write to device first then increase the sequence number
                tcpConnection.setCurrentSequenceNumber(tcpConnection.getCurrentSequenceNumber() + mssData.length);
                Log.d(TcpConnection.class.getName(),
                        "<<<<---- Receive remote data write ack to device, current connection: " +
                                tcpConnection + ", remote data size: " + mssData.length);
                Log.v(TcpConnection.class.getName(),
                        "<<<<---- Remote data:\n\n" + ByteBufUtil.prettyHexDump(Unpooled.wrappedBuffer(mssData)) +
                                "\n\n");
            }
        }
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) throws Exception {
        AttributeKey<TcpConnection> tcpConnectionKey = AttributeKey.valueOf(IVpnConst.TCP_CONNECTION);
        TcpConnection tcpConnection = ctx.channel().attr(tcpConnectionKey).get();
        if (tcpConnection == null) {
            ctx.close();
            return;
        }
        if (tcpConnection.getStatus() == TcpConnectionStatus.CLOSED) {
            tcpConnection.finallyCloseTcpConnection();
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) throws Exception {
        AttributeKey<TcpConnection> tcpConnectionKey = AttributeKey.valueOf(IVpnConst.TCP_CONNECTION);
        TcpConnection tcpConnection = ctx.channel().attr(tcpConnectionKey).get();
        Log.e(TcpConnection.class.getName(),
                "<<<<---- Exception happen, current connection: " +
                        tcpConnection, cause);
        if (tcpConnection != null) {
            tcpConnection.writeRstToDevice();
            ctx.close();
            tcpConnection.finallyCloseTcpConnection();
        }
    }
}
