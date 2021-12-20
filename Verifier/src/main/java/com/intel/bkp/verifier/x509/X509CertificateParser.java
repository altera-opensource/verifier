/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2021 Intel Corporation. All Rights Reserved.
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

package com.intel.bkp.verifier.x509;

import com.intel.bkp.ext.core.certificate.X509CertificateUtils;
import com.intel.bkp.ext.crypto.exceptions.X509CertificateParsingException;
import com.intel.bkp.verifier.exceptions.X509ParsingException;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.intel.bkp.ext.crypto.x509.X509CertificateParser.toX509Certificate;

@Slf4j
public class X509CertificateParser {

    private static final String FAIL_TO_PARSE_MESSAGE = "Failed to parse CRL Distribution Points "
        + "from attestation certificate.";

    public Optional<String> getPathToCrlDistributionPoint(X509Certificate certificate) {
        final List<String> crlUrls;
        try {
            if (!X509CertificateUtils.containsExtension(certificate, Extension.cRLDistributionPoints)) {
                return Optional.empty();
            }

            final List<GeneralNames> generalNamesList =
                extractCrlUrls(extractDistributionPoints(certificate));

            crlUrls = generalNamesList
                .stream()
                .map(GeneralNames::getNames)
                .flatMap(Stream::of)
                .filter(x -> x.getTagNo() == (GeneralName.uniformResourceIdentifier))
                .map(x -> DERIA5String.getInstance(x.getName()).getString())
                .collect(Collectors.toList());
        } catch (Exception e) {
            throw new X509ParsingException(FAIL_TO_PARSE_MESSAGE, e);
        }

        if (crlUrls.size() < 1) {
            throw new X509ParsingException(FAIL_TO_PARSE_MESSAGE);
        }

        if (crlUrls.size() > 1) {
            log.warn("Multiple CRL Distribution Points in certificate. Checking revocation status against first CRL.");
        }

        return Optional.of(crlUrls.get(0));
    }

    public Optional<String> findPathToIssuerCertificate(X509Certificate certificate) {
        final byte[] authorityInfoAccess = certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        return tryGetAccessDescriptions(authorityInfoAccess)
            .filter(descriptions -> descriptions.length > 0)
            .map(descriptions -> getLocationName(descriptions[0]))
            .filter(StringUtils::isNotBlank);
    }

    public String getPathToIssuerCertificate(X509Certificate certificate) {
        return findPathToIssuerCertificate(certificate)
            .orElseThrow(() -> new X509ParsingException("No AuthorityInformationAccess in certificate."));
    }

    public X509Certificate toX509(String certificate) {
        return toX509(certificate.getBytes());
    }

    public X509Certificate toX509(byte[] certificate) {
        try {
            return toX509Certificate(certificate);
        } catch (X509CertificateParsingException e) {
            throw new X509ParsingException("Failed to parse X.509 certificates.", e);
        }
    }

    public Optional<X509Certificate> tryToX509(byte[] certificate) {
        try {
            return Optional.of(toX509Certificate(certificate));
        } catch (X509CertificateParsingException e) {
            return Optional.empty();
        }
    }

    private Optional<AccessDescription[]> tryGetAccessDescriptions(byte[] authorityInfoAccess) {
        if (authorityInfoAccess == null) {
            return Optional.empty();
        }
        try {
            return Optional.ofNullable(AuthorityInformationAccess.getInstance(
                    JcaX509ExtensionUtils.parseExtensionValue(authorityInfoAccess))
                .getAccessDescriptions());
        } catch (IOException e) {
            log.warn("Failed to parse AuthorityInformationAccess from certificate.", e);
        }

        return Optional.empty();
    }

    private ASN1Primitive getOctetString(byte[] octetString) throws Exception {
        try (ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(octetString))) {
            return oAsnInStream.readObject();
        }
    }

    private String getLocationName(AccessDescription accessDescription) {
        return accessDescription.getAccessLocation().getName().toString();
    }

    private List<GeneralNames> extractCrlUrls(Optional<DistributionPoint[]> dpArray) {
        return Arrays.stream(dpArray.orElse(new DistributionPoint[] {}))
            .map(DistributionPoint::getDistributionPoint)
            .filter(Objects::nonNull)
            .filter(x -> x.getType() == DistributionPointName.FULL_NAME)
            .map(x -> GeneralNames.getInstance(x.getName()))
            .collect(Collectors.toList());
    }

    private Optional<DistributionPoint[]> extractDistributionPoints(X509Certificate certificate) throws Exception {
        final byte[] crlDistributionPoints = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());

        final DEROctetString derCrl = (DEROctetString)getOctetString(crlDistributionPoints);
        final byte[] crldpExtOctets = derCrl.getOctets();
        final CRLDistPoint distPoint = CRLDistPoint.getInstance(getOctetString(crldpExtOctets));

        return Optional.ofNullable(distPoint.getDistributionPoints());
    }
}
