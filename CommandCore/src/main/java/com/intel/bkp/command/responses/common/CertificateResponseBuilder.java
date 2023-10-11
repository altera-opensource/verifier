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

import com.intel.bkp.command.model.StructureType;
import com.intel.bkp.core.endianness.StructureBuilder;
import com.intel.bkp.core.exceptions.ParseStructureException;
import com.intel.bkp.utils.ByteBufferSafe;
import lombok.Getter;
import lombok.Setter;

import static com.intel.bkp.command.model.StructureField.CERTIFICATE_PROCESS_STATUS;

@Getter
@Setter
public class CertificateResponseBuilder
    extends StructureBuilder<CertificateResponseBuilder, CertificateResponse> {

    private byte[] certificateProcessStatus = new byte[Integer.BYTES];
    private byte[] responseData = new byte[0];

    public CertificateResponseBuilder() {
        super(StructureType.CERTIFICATE_RESP);
    }

    @Override
    public CertificateResponseBuilder self() {
        return this;
    }

    @Override
    public CertificateResponse build() {
        CertificateResponse certificateResponse = new CertificateResponse();
        certificateResponse.setCertificateProcessStatus(
            convert(certificateProcessStatus, CERTIFICATE_PROCESS_STATUS));
        certificateResponse.setResponseData(responseData);
        return certificateResponse;
    }

    @Override
    public CertificateResponseBuilder parse(ByteBufferSafe buffer) throws ParseStructureException {
        buffer.get(certificateProcessStatus);
        responseData = buffer.getRemaining();

        certificateProcessStatus = convert(certificateProcessStatus,
            CERTIFICATE_PROCESS_STATUS);
        return this;
    }

}
