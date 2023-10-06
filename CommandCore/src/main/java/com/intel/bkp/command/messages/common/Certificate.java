/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2023 Intel Corporation. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * **************************************************************************
 *
 */

package com.intel.bkp.command.messages.common;

import com.intel.bkp.command.logger.ILogger;
import com.intel.bkp.command.messages.utils.AssetLoggingUtils;
import com.intel.bkp.command.model.Message;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.codec.digest.DigestUtils;

import java.nio.ByteBuffer;

import static com.intel.bkp.utils.HexConverter.toHex;

@Getter
@Setter
public class Certificate implements Message, ILogger {

    private byte[] reservedHeader = new byte[0];
    private byte[] userAesRootKeyCertificate = new byte[0];

    @Override
    public byte[] array() {
        return ByteBuffer.allocate(reservedHeader.length + userAesRootKeyCertificate.length)
            .put(reservedHeader)
            .put(userAesRootKeyCertificate)
            .array();
    }

    @Override
    public String hex() {
        final String metadata = toHex(
            ByteBuffer.allocate(reservedHeader.length)
                .put(reservedHeader)
                .array()
        );

        final String certHash = toHex(DigestUtils.sha384(userAesRootKeyCertificate));
        return new StringBuilder()
            .append(metadata)
            .append(AssetLoggingUtils.getHiddenAsset(certHash))
            .toString();
    }
}
