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

package com.intel.bkp.verifier.sigma;

import com.intel.bkp.core.psgcertificate.exceptions.PsgInvalidSignatureException;
import com.intel.bkp.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.verifier.command.responses.attestation.GetMeasurementResponse;
import com.intel.bkp.verifier.exceptions.SigmaException;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@NoArgsConstructor
public class GetMeasurementVerifier {

    private GetMeasurementPakSubKeySignatureVerifier
        pakSignatureVerifier = new GetMeasurementPakSubKeySignatureVerifier();
    private SigmaM2VerifierDhPubKeyVerifier dhPubKeyVerifier = new SigmaM2VerifierDhPubKeyVerifier();

    public void verify(PublicKey aliasPubKey, GetMeasurementResponse response, EcdhKeyPair serviceDhKeyPair) {
        verifySignature(response, aliasPubKey);
        verifyVerifierDhPubKey(response, serviceDhKeyPair);
    }

    private void verifySignature(GetMeasurementResponse response, PublicKey pufAttestationPubKey) {
        try {
            pakSignatureVerifier.verify(pufAttestationPubKey, response);
        } catch (PsgInvalidSignatureException e) {
            throw new SigmaException("GetMeasurementResponse signature "
                + "verification with PufAttestationPubKey failed.", e);
        }
    }

    private void verifyVerifierDhPubKey(GetMeasurementResponse response, EcdhKeyPair serviceDhKeyPair) {
        dhPubKeyVerifier.verify(serviceDhKeyPair.getPublicKey(), response.getVerifierDhPubKey());
    }
}
