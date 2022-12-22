package com.ppaass.agent.service.handler;

import android.util.Log;
import com.ppaass.agent.service.IVpnConst;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.ChannelHandlerContext;
import io.netty.handler.codec.ByteToMessageDecoder;
import net.jpountz.lz4.LZ4Factory;

import java.util.List;

public class PpaassMessageDecoder extends ByteToMessageDecoder {
    private static final int COMPRESS_FIELD_LENGTH = 1;
    private static final int BODY_LENGTH_FIELD_LENGTH = 8;
    private static final int HEADER_LENGTH =
            IVpnConst.PPAASS_PROTOCOL_FLAG.length() + COMPRESS_FIELD_LENGTH + BODY_LENGTH_FIELD_LENGTH;
    private boolean readHeader;
    private int bodyLength;
    private boolean compressed;

    public PpaassMessageDecoder() {
        this.readHeader = true;
    }

    @Override
    protected void decode(ChannelHandlerContext ctx, ByteBuf in, List<Object> out) {
        if (this.readHeader) {
            //Read header
            if (in.readableBytes() < HEADER_LENGTH) {
                return;
            }
            byte[] flagBytes = new byte[IVpnConst.PPAASS_PROTOCOL_FLAG.length()];
            in.readBytes(flagBytes);
            var flag = new String(flagBytes);
            if (!IVpnConst.PPAASS_PROTOCOL_FLAG.equals(flag)) {
                Log.e(PpaassMessageDecoder.class.getName(), "Receive invalid ppaass protocol flag: " + flag);
                throw new UnsupportedOperationException("Receive invalid ppaass protocol flag: " + flag);
            }
            this.compressed = in.readBoolean();
            this.bodyLength = (int) in.readLong();
            this.readHeader = false;
            return;
        }
        //Read body
        if (in.readableBytes() < this.bodyLength) {
            return;
        }
        var bodyBuf = Unpooled.buffer(this.bodyLength);
        in.readBytes(bodyBuf);
        if (this.compressed) {
            var lz4Decompressor = LZ4Factory.fastestInstance().safeDecompressor();
            var compressedBodyBytes = new byte[bodyLength];
            bodyBuf.readBytes(compressedBodyBytes);
            var decompressBodyBytes =
                    lz4Decompressor.decompress(compressedBodyBytes, 0, bodyLength, bodyLength);
            bodyBuf = Unpooled.wrappedBuffer(decompressBodyBytes);
        }
        var result = PpaassMessageUtil.INSTANCE.convertBytesToPpaassMessage(bodyBuf);
        this.readHeader = true;
        this.compressed = false;
        this.bodyLength = 0;
        out.add(result);
    }
}
