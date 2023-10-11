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

package com.intel.bkp.fpgacerts.cbor.signer.cose.sign;

import com.intel.bkp.crypto.CryptoUtils;
import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.fpgacerts.cbor.signer.cose.RimAsn1;
import com.intel.bkp.fpgacerts.cbor.signer.cose.exception.CoseException;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.Optional;

import static com.intel.bkp.crypto.constants.CryptoConstants.SHA256_WITH_ECDSA;
import static com.intel.bkp.crypto.constants.CryptoConstants.SHA384_WITH_ECDSA;
import static com.intel.bkp.crypto.constants.CryptoConstants.SHA512_WITH_ECDSA;
import static com.intel.bkp.utils.HexConverter.toHex;

@Slf4j
public class SignatureVerifier {

    public static boolean verify(AlgorithmId algorithm, byte[] payload, byte[] signature, CborKeyPair cborKeyPair)
        throws CoseException {

        final String algName = switch (algorithm) {
            case ECDSA_256 -> SHA256_WITH_ECDSA;
            case ECDSA_384 -> SHA384_WITH_ECDSA;
            case ECDSA_521 -> SHA512_WITH_ECDSA;
        };

        final var publicKey = Optional.ofNullable(cborKeyPair.getPublicKey())
            .orElseThrow(() -> new CoseException("Public key required to verify"));

        return verify(payload, signature, algName, publicKey);
    }

    private static boolean verify(byte[] payload, byte[] signature, String algName,
                                  PublicKey pubKey) throws CoseException {
        try {
            final var sig = Signature.getInstance(algName, CryptoUtils.getBouncyCastleProvider());
            sig.initVerify(pubKey);
            sig.update(payload);
            log.trace("PubKey: {}", toHex(pubKey.getEncoded()));
            log.trace("Payload: {}", toHex(payload));
            log.trace("Signature before convert: {}", toHex(signature));

            signature = convertConcatToDer(signature);

            log.trace("Signature: {}", toHex(signature));

            return sig.verify(signature);
        } catch (Exception ex) {
            throw new CoseException("Signature verification failure", ex);
        }
    }

    private static byte[] convertConcatToDer(byte[] concat) throws CoseException {
        int len = concat.length / 2;
        byte[] r = Arrays.copyOfRange(concat, 0, len);
        byte[] s = Arrays.copyOfRange(concat, len, concat.length);

        return RimAsn1.encodeSignature(r, s);
    }
}
