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

package com.intel.bkp.test.model;

import com.intel.bkp.crypto.x509.generation.ICrlParams;
import com.intel.bkp.crypto.x509.generation.X509CrlIssuerDTO;
import lombok.RequiredArgsConstructor;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.cert.X509v2CRLBuilder;

import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

@RequiredArgsConstructor
public class SerialNumberCrlParams implements ICrlParams {

    private static final int VALIDITY_YEARS = 5;
    private static final BigInteger CRL_NUMBER = BigInteger.ZERO;

    private final X509CrlIssuerDTO issuerDTO;
    private final List<BigInteger> serialNumbersToRevoke;

    @Override
    public X509CrlIssuerDTO getIssuer() {
        return issuerDTO;
    }

    @Override
    public BigInteger getCrlNumber() {
        return CRL_NUMBER;
    }

    @Override
    public Date getNextUpdate(Date now) {
        return getDatePlusYears(now, VALIDITY_YEARS);
    }

    @Override
    public void fillEntries(X509v2CRLBuilder crlBuilder) {
        final var now = new Date();
        serialNumbersToRevoke.forEach(
            sn -> crlBuilder.addCRLEntry(
                sn,
                now,
                CRLReason.keyCompromise
            )
        );
    }

    private Date getDatePlusYears(Date date, int years) {
        final Calendar calendar = Calendar.getInstance();
        calendar.setTime(date);
        calendar.add(Calendar.YEAR, years);
        return calendar.getTime();
    }
}
