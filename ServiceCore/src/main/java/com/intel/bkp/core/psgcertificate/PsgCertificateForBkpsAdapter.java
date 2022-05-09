/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2022 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.core.psgcertificate;

import com.intel.bkp.core.endianess.EndianessActor;
import com.intel.bkp.core.psgcertificate.exceptions.PsgCertificateException;
import com.intel.bkp.core.psgcertificate.model.CertificateEntryWrapper;
import com.intel.bkp.core.psgcertificate.model.PsgCertificateType;
import com.intel.bkp.core.psgcertificate.model.PsgRootCertMagic;
import com.intel.bkp.crypto.CertificateEncoder;
import com.intel.bkp.utils.ByteBufferSafe;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

import java.nio.ByteOrder;
import java.util.LinkedList;
import java.util.List;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class PsgCertificateForBkpsAdapter {

    public static List<CertificateEntryWrapper> parse(String encodedChain) throws PsgCertificateException {
        byte[] decodedChain = CertificateEncoder.sanitizeChainPayloadHex(encodedChain);

        ByteBufferSafe decodedChainBuffer = ByteBufferSafe.wrap(decodedChain);

        final LinkedList<CertificateEntryWrapper> dataList = new LinkedList<>();
        while (hasAtLeastTwoMoreFieldsToRead(decodedChainBuffer)) {
            decodedChainBuffer.mark();
            int magic = decodedChainBuffer.getInt(ByteOrder.LITTLE_ENDIAN);
            int length = decodedChainBuffer.getInt(ByteOrder.LITTLE_ENDIAN);

            if (PsgCertificateEntryBuilder.PUBLIC_KEY_ENTRY_MAGIC == magic) {
                decodedChainBuffer.reset();
                dataList.add(getLeafCertificate(decodedChainBuffer, length));
            } else if (PsgRootCertMagic.isValid(magic)) {
                decodedChainBuffer.reset();
                dataList.add(getRootCertificate(decodedChainBuffer, length));
            }
        }
        return dataList;
    }

    private static boolean hasAtLeastTwoMoreFieldsToRead(ByteBufferSafe decodedChainBuffer) {
        return decodedChainBuffer.remaining() >= 2 * Integer.BYTES;
    }

    private static CertificateEntryWrapper getRootCertificate(ByteBufferSafe bufferSafe, int length)
        throws PsgCertificateException {
        byte[] certificateContent = bufferSafe.arrayFromInt(length);
        bufferSafe.get(certificateContent);
        return new CertificateEntryWrapper(PsgCertificateType.ROOT,
            new PsgCertificateRootEntryBuilder()
                .withActor(EndianessActor.FIRMWARE)
                .parse(certificateContent)
                .withActor(EndianessActor.SERVICE)
                .build()
                .array()
        );
    }

    private static CertificateEntryWrapper getLeafCertificate(ByteBufferSafe bufferSafe, int length)
        throws PsgCertificateException {
        byte[] certificateContent = bufferSafe.arrayFromInt(length);
        bufferSafe.get(certificateContent);
        return new CertificateEntryWrapper(PsgCertificateType.LEAF,
            new PsgCertificateEntryBuilder()
                .withActor(EndianessActor.FIRMWARE)
                .parse(certificateContent)
                .withActor(EndianessActor.SERVICE)
                .build()
                .array()
        );
    }
}
