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

package com.intel.bkp.command.responses.common;

import com.intel.bkp.command.exception.JtagResponseException;
import com.intel.bkp.command.model.CertificateRequestType;
import com.intel.bkp.utils.ByteBufferSafe;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import static com.intel.bkp.utils.HexConverter.toHex;

@Setter
@Slf4j
public class GetCertificateResponseBuilder {

    private static final int BOUNDARY = 4092; // 4kb total

    private byte[] certificateType = new byte[Integer.BYTES];
    private byte[] certificateBlob = new byte[0];
    private CertificateRequestType certificateTypeValue;

    public GetCertificateResponse build() {
        GetCertificateResponse response = new GetCertificateResponse();
        response.setCertificateType(certificateType);
        response.setCertificateBlob(certificateBlob);
        response.setCertificateTypeValue(certificateTypeValue);
        return response;
    }

    public GetCertificateResponseBuilder parse(byte[] message) {
        log.debug("Parsing GetCertificateResponse.");
        final ByteBufferSafe buffer = ByteBufferSafe.wrap(message)
            .get(certificateType);

        certificateTypeValue = parseCertificateType(certificateType);
        log.debug("Certificate type: {}.", certificateTypeValue.name());

        if (buffer.remaining() == 0) {
            throw new JtagResponseException("Response does not contain any certificate data.");
        }

        if (buffer.remaining() > BOUNDARY) {
            throw new JtagResponseException(String.format("Response data contains more information %d than limit %d",
                buffer.remaining(), BOUNDARY));
        }

        certificateBlob = buffer.getRemaining();
        return this;
    }

    private CertificateRequestType parseCertificateType(byte[] certificateType) {
        try {
            return CertificateRequestType.findByType(certificateType);
        } catch (IllegalArgumentException e) {
            throw new JtagResponseException(String.format("Unknown certificate type: %s", toHex(certificateType)));
        }
    }
}
