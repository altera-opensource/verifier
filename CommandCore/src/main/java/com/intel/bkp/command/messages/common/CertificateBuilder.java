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

import com.intel.bkp.utils.ByteBufferSafe;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PACKAGE)
public class CertificateBuilder {

    private final byte[] reservedHeader = new byte[Integer.BYTES];
    private byte[] userAesRootKeyCertificate;

    public CertificateBuilder testProgram(boolean isTestProgram) {
        log.debug("TEST_PROGRAM flag is " + (isTestProgram ? "set." : "unset."));
        this.reservedHeader[3] = isTestProgram ? (byte)0x80 : 0;
        return this;
    }

    public CertificateBuilder(byte[] userAesRootKeyCertificate) {
        this.userAesRootKeyCertificate = userAesRootKeyCertificate;
    }

    public Certificate build() {
        Certificate certificate = new Certificate();
        certificate.setReservedHeader(reservedHeader);
        certificate.setUserAesRootKeyCertificate(userAesRootKeyCertificate);
        return certificate;
    }

    public CertificateBuilder parse(byte[] message) {
        this.userAesRootKeyCertificate = new byte[message.length - reservedHeader.length];
        ByteBufferSafe.wrap(message).get(reservedHeader).getAll(userAesRootKeyCertificate);
        return this;
    }
}
