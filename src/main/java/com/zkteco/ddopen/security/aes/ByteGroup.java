package com.zkteco.ddopen.security.aes;

import java.util.ArrayList;

/**
 * @author Larry.lv
 * @since 1.0.0
 * Create Date 2018-10-15 17:09
 * Copyright © 1985-2018 ZKTeco Inc.All right reserved.
 **/

public class ByteGroup {
    ArrayList<Byte> byteContainer = new ArrayList<Byte>();

    public byte[] toBytes() {
        byte[] bytes = new byte[byteContainer.size()];
        for (int i = 0; i < byteContainer.size(); i++) {
            bytes[i] = byteContainer.get(i);
        }
        return bytes;
    }

    public ByteGroup addBytes(byte[] bytes) {
        for (byte b : bytes) {
            byteContainer.add(b);
        }
        return this;
    }

    public int size() {
        return byteContainer.size();
    }
}

