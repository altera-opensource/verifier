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

/*
 * Copyright (c) 2016,
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of COSE-JAVA nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.intel.bkp.fpgacerts.cbor.signer.cose.sign;

import com.intel.bkp.fpgacerts.cbor.signer.cose.CborKeyPair;
import com.intel.bkp.fpgacerts.cbor.signer.cose.exception.CoseException;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.AlgorithmId;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Optional;

import static com.intel.bkp.crypto.CryptoUtils.getBouncyCastleProvider;

public class CborSigner {

    public byte[] sign(byte[] payload, AlgorithmId algorithm, CborKeyPair cborKeyPair) throws CoseException {
        final var privateKey = Optional.ofNullable(cborKeyPair.getPrivateKey())
            .orElseThrow(() -> new CoseException("Private key required to sign"));

        byte[] result;
        try {
            final var sig = Signature.getInstance(algorithm.getShaAlgorithmName(), getBouncyCastleProvider());
            sig.initSign(privateKey);
            sig.update(payload);
            result = sig.sign();
            result = convertDerToConcat(result, algorithm.getSignatureLength());
        } catch (NoSuchAlgorithmException ex) {
            throw new CoseException("Algorithm not supported", ex);
        } catch (Exception ex) {
            throw new CoseException("Signature failure", ex);
        }
        return result;
    }

    private static byte[] convertDerToConcat(byte[] der, int len) throws CoseException {
        // assumes SEQUENCE is organized as "R + S"
        int lengthK = 4;
        if (der[0] != 0x30) {
            throw new CoseException("Unexpected signature input");
        }
        if ((der[1] & 0x80) != 0) {
            // offset actually 4 + (7-bits of byte 1)
            lengthK = 4 + (der[1] & 0x7f);
        }

        // calculate start/end of R
        int offsetR = lengthK;
        int lengthR = der[offsetR - 1];
        int paddingR = 0;
        if (lengthR > len) {
            offsetR += (lengthR - len);
            lengthR = len;
        } else {
            paddingR = (len - lengthR);
        }
        // copy R
        byte[] concat = new byte[len * 2];
        System.arraycopy(der, offsetR, concat, paddingR, lengthR);

        // calculate start/end of S
        int offsetS = offsetR + lengthR + 2;
        int lengthS = der[offsetS - 1];
        int paddingS = 0;
        if (lengthS > len) {
            offsetS += (lengthS - len);
            lengthS = len;
        } else {
            paddingS = (len - lengthS);
        }
        // copy S
        System.arraycopy(der, offsetS, concat, len + paddingS, lengthS);

        return concat;
    }
}
