package com.ppaass.agent.service.handler.tcp;

import android.util.Log;
import com.ppaass.agent.protocol.message.Message;
import com.ppaass.agent.service.IVpnConst;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.MessageToByteEncoder;
import net.jpountz.lz4.LZ4Compressor;
import net.jpountz.lz4.LZ4Factory;

public class PpaassMessageEncoder extends MessageToByteEncoder<Message> {
    private final boolean compress;

    public PpaassMessageEncoder(boolean compress) {
        this.compress = compress;
    }

    @Override
    protected void encode(ChannelHandlerContext ctx, Message msg, ByteBuf out) throws Exception {
        out.writeBytes(IVpnConst.PPAASS_PROTOCOL_FLAG.getBytes());
        out.writeBoolean(this.compress);
        //Message body
        byte[] messageBytes = PpaassMessageUtil.INSTANCE.generateMessageBytes(msg);
        if (compress) {
            LZ4Compressor lz4Compressor = LZ4Factory.fastestInstance().fastCompressor();
            byte[] compressedBodyBytes = lz4Compressor.compress(messageBytes);
            out.writeLong(compressedBodyBytes.length);
            out.writeBytes(compressedBodyBytes);
            Log.d(PpaassMessageEncoder.class.getName(),
                    "Write following data to remote(compressed):\n" + ByteBufUtil.prettyHexDump(out) + "\n");
            return;
        }
        out.writeLong(messageBytes.length);
        out.writeBytes(messageBytes);
        Log.d(PpaassMessageEncoder.class.getName(),
                "Write following data to remote(non-compress):\n" + ByteBufUtil.prettyHexDump(out) + "\n");
    }
}
