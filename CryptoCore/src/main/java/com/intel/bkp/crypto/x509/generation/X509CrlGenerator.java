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

package com.intel.bkp.crypto.x509.generation;

import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.exceptions.CrlGenerationFailed;
import com.intel.bkp.crypto.x509.utils.X509CrlUtils;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509v2CRLBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Optional;

import static com.intel.bkp.crypto.x509.utils.KeyIdentifierUtils.createAuthorityKeyIdentifier;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class X509CrlGenerator {

    public static X509CRL generateCrl(ICrlParams crlParams) throws CrlGenerationFailed {
        return generateCrl(crlParams, Optional.of(new Date()));
    }

    public static X509CRL generateCrl(ICrlParams crlParams, Optional<Date> nowOptional) throws CrlGenerationFailed {
        try {
            final X509Certificate issuerCertificate = crlParams.getIssuer().getIssuerCertificate();
            final Date thisUpdate = nowOptional.orElse(new Date());
            final X509v2CRLBuilder crlBuilder = new JcaX509v2CRLBuilder(issuerCertificate, thisUpdate);

            crlBuilder.addExtension(
                Extension.cRLNumber, false, new CRLNumber(crlParams.getCrlNumber()));
            crlBuilder.addExtension(
                Extension.authorityKeyIdentifier, false, createAuthorityKeyIdentifier(issuerCertificate));
            nowOptional.ifPresent(now -> crlBuilder.setNextUpdate(crlParams.getNextUpdate(now)));
            crlParams.fillEntries(crlBuilder);

            return buildCrl(crlParams.getIssuer(), crlBuilder);
        } catch (IOException | CertificateEncodingException | OperatorCreationException | CRLException
            | NoSuchAlgorithmException e) {
            throw new CrlGenerationFailed("Failed to generate CRL.", e);
        }
    }

    private static X509CRL buildCrl(X509CrlIssuerDTO issuerDTO,
                                    X509v2CRLBuilder crlBuilder) throws OperatorCreationException, CRLException {
        final ContentSigner contentSigner = new JcaContentSignerBuilder(CryptoConstants.SHA384_WITH_ECDSA)
            .setProvider(issuerDTO.getProvider())
            .build(issuerDTO.getIssuerPrivateKey());
        final X509CRLHolder x509CrlHolder = crlBuilder.build(contentSigner);
        return X509CrlUtils.getCrl(x509CrlHolder);
    }
}
