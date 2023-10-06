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

package com.intel.bkp.fpgacerts.cbor.signer.cose;

import com.intel.bkp.fpgacerts.cbor.signer.cose.exception.CoseException;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.KeyKeys;
import com.intel.bkp.fpgacerts.cbor.signer.cose.model.TagValue;
import com.upokecenter.cbor.CBORObject;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class CborKeyPair {

    protected CBORObject keyMap = CBORObject.NewMap();
    @Getter
    private PrivateKey privateKey;
    @Getter
    private PublicKey publicKey;

    @Setter
    @Getter
    private Object userData;

    public static CborKeyPair fromPublicKey(PublicKey publicKey) throws CoseException {
        return fromKeyPair(publicKey, null);
    }

    public static CborKeyPair fromKeyPair(PublicKey publicKey, PrivateKey privateKey) throws CoseException {
        final CborKeyPair cborKeyPair = new CborKeyPair();
        if (publicKey != null) {
            cborKeyPair.processPublicKey(publicKey);
        }
        if (privateKey != null) {
            cborKeyPair.processPrivateKey(privateKey);
        }
        return cborKeyPair;
    }

    private void processPublicKey(PublicKey pubKey) throws CoseException {
        final var spki = RimAsn1.decodeSubjectPublicKeyInfo(pubKey.getEncoded());
        final var alg = spki.get(0).getTags();

        if (!Arrays.equals(alg.get(0).getValue(), RimAsn1.OID_EC_PUBLIC_KEY)) {
            throw new CoseException("Unsupported Algorithm");
        }

        final byte[] oid = Optional.ofNullable(alg.get(1))
            .map(TagValue::getValue)
            .orElseThrow(() -> new CoseException("Invalid SPKI structure"));

        populateKeyMap(oid);

        final byte[] keyData = spki.get(1).getValue();
        final byte firstItem = keyData[1];
        if (firstItem == 2 || firstItem == 3) {
            keyMap.Add(KeyKeys.EC_X.getCbor(), Arrays.copyOfRange(keyData, 2, keyData.length));
            keyMap.Add(KeyKeys.EC_Y.getCbor(), firstItem != 2);
        } else if (firstItem == 4) {
            final int keyLength = (keyData.length - 2) / 2;
            keyMap.Add(KeyKeys.EC_X.getCbor(), Arrays.copyOfRange(keyData, 2, 2 + keyLength));
            keyMap.Add(KeyKeys.EC_Y.getCbor(), Arrays.copyOfRange(keyData, 2 + keyLength, keyData.length));
        } else {
            throw new CoseException("Invalid key data");
        }

        this.publicKey = pubKey;
    }

    private void processPrivateKey(PrivateKey privateKey) throws CoseException {
        final List<TagValue> pkl = RimAsn1.decodePKCS8Structure(privateKey.getEncoded());
        if (pkl.get(0).getTag() != 2) {
            throw new CoseException("Invalid PKCS8 structure");
        }
        final List<TagValue> alg = pkl.get(1).getTags();

        if (!Arrays.equals(alg.get(0).getValue(), RimAsn1.OID_EC_PUBLIC_KEY)) {
            throw new CoseException("Unsupported Algorithm");
        }

        final byte[] oid = alg.get(1).getValue();
        if (oid == null) {
            throw new CoseException("Invalid PKCS8 structure");
        }
        if (!keyMap.ContainsKey(KeyKeys.KEY_TYPE.getCbor())) {
            populateKeyMap(oid);
        } else {
            if (!this.get(KeyKeys.KEY_TYPE).equals(KeyKeys.KEY_TYPE_EC)) {
                throw new CoseException("Public or private key don't match");
            }
        }

        final List<TagValue> pkdl = RimAsn1.decodePKCS8EC(pkl);
        if (pkdl.get(1).getTag() != 4) {
            throw new CoseException("Invalid PKCS8 structure");
        }
        byte[] keyData = pkdl.get(1).getValue();
        keyMap.Add(KeyKeys.EC_D.getCbor(), keyData);

        this.privateKey = privateKey;
    }

    public void add(KeyKeys keyValue, CBORObject value) {
        keyMap.Add(keyValue.getCbor(), value);
    }

    public CBORObject get(KeyKeys keyValue) {
        return keyMap.get(keyValue.getCbor());
    }

    private void populateKeyMap(byte[] oid) throws CoseException {
        keyMap.Add(KeyKeys.KEY_TYPE.getCbor(), KeyKeys.KEY_TYPE_EC);
        keyMap.Add(KeyKeys.EC_CURVE.getCbor(), RimAsn1.oidToCborEcCurve(oid));
    }
}
