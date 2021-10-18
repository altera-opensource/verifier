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

import com.intel.bkp.verifier.exceptions.CertificateChainValidationException;
import lombok.extern.slf4j.Slf4j;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;

@Slf4j
public class X509CertificateIssuerVerifier {

    public void verify(final X509Certificate child, final X509Certificate parent)
        throws CertificateChainValidationException {

        final var childIssuer = child.getIssuerX500Principal();
        final var parentSubject = parent.getSubjectX500Principal();
        if (!match(childIssuer, parentSubject)) {
            handleMismatchedIssuer(child, parent);
        }
    }

    private boolean match(final X500Principal first, final X500Principal second) {
        try {
            final var firstRdns = new LdapName(first.getName()).getRdns();
            final var secondRdns = new LdapName(second.getName()).getRdns();
            return firstRdns.size() == secondRdns.size()
                && firstRdns.containsAll(secondRdns);
        } catch (InvalidNameException e) {
            log.error("Failed to parse X500Principal: ", e);
            return false;
        }
    }

    private void handleMismatchedIssuer(final X509Certificate child, final X509Certificate parent)
        throws CertificateChainValidationException {

        final var errorMessage = String.format(
            "Certificate has Issuer (%s) that does not match Subject of parent certificate (%s).",
            child.getIssuerDN(), parent.getSubjectDN());
        throw new CertificateChainValidationException(errorMessage);
    }
}
