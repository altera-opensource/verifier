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

package com.intel.bkp.verifier.dp;

import com.intel.bkp.fpgacerts.chain.DistributionPointCertificate;
import com.intel.bkp.fpgacerts.dice.IpcsCertificateFetcher;
import com.intel.bkp.verifier.exceptions.ChainFetchingException;
import com.intel.bkp.verifier.service.certificate.AppContext;

import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.function.Supplier;

public class DistributionPointIpcsCertificateFetcher extends IpcsCertificateFetcher {

    private static final String DEVICE_ID_CERT_NAME = "IPCS DeviceId";
    private static final String IID_UDS_CERT_NAME = "IPCS IID UDS";
    private static final String ENROLLMENT_CERT_NAME = "IPCS Enrollment";

    public DistributionPointIpcsCertificateFetcher() {
        this(AppContext.instance());
    }

    DistributionPointIpcsCertificateFetcher(AppContext appContext) {
        super(new DistributionPointCertificateFetcher(appContext.getDpConnector()), appContext.getDpPathCer());
    }

    public X509Certificate fetchIpcsDeviceIdX509Cert() {
        return fetchAsX509Certificate(super::fetchIpcsDeviceIdCert, DEVICE_ID_CERT_NAME);
    }

    public X509Certificate fetchIpcsIidUdsX509Cert() {
        return fetchAsX509Certificate(super::fetchIpcsIidUdsCert, IID_UDS_CERT_NAME);
    }

    public X509Certificate fetchIpcsEnrollmentX509Cert() {
        return fetchAsX509Certificate(super::fetchIpcsEnrollmentCert, ENROLLMENT_CERT_NAME);
    }

    private X509Certificate fetchAsX509Certificate(Supplier<Optional<DistributionPointCertificate>> certSupplier,
                                                   String certName) {
        return certSupplier
            .get()
            .map(DistributionPointCertificate::getX509Cert)
            .orElseThrow(() -> new ChainFetchingException(
                "%s certificate not found on Distribution Point.".formatted(certName)));
    }
}
