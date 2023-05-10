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

package com.intel.bkp.core.utils.provider;

import org.bouncycastle.util.encoders.Hex;

import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class EC extends KeyPairGeneratorSpi {

    public void initialize(AlgorithmParameterSpec params, SecureRandom random) {

    }

    @Override
    public void initialize(int keysize, SecureRandom random) {

    }

    @Override
    public KeyPair generateKeyPair() {
        return new KeyPair(
            new PublicKey() {
                @Override
                public String getAlgorithm() {
                    return null;
                }

                @Override
                public String getFormat() {
                    return null;
                }

                @Override
                public byte[] getEncoded() {
                    String publicKeyEncodedHexString =
                        "3076301006072a8648ce3d020106052b8104002203620004b0aa465397f2333f094642c0c226ac881f03f26579"
                            + "1408e438a46c2021eeee1f30210e7db208c8ab859f7e0c9959fcc9010d125e41d9402bf6f708b9309804"
                            + "ccb69d5d095fdb74d0ac9c2e8c34c7d6e08283f7a1b2c63d9ffef0b8bf94a01ec2";

                    return Hex.decode(publicKeyEncodedHexString);
                }
            },
            new PrivateKey() {
                @Override
                public String getAlgorithm() {
                    return null;
                }

                @Override
                public String getFormat() {
                    return null;
                }

                @Override
                public byte[] getEncoded() {
                    String publicKeyEncodedHexString =
                        "3076301006072a8648ce3d020106052b8104002203620004b0aa465397f2333f094642c0c226ac881f03f26579"
                            + "1408e438a46c2021eeee1f30210e7db208c8ab859f7e0c9959fcc9010d125e41d9402bf6f708b9309804"
                            + "ccb69d5d095fdb74d0ac9c2e8c34c7d6e08283f7a1b2c63d9ffef0b8bf94a01ec2";

                    return Hex.decode(publicKeyEncodedHexString);
                }
            }
        );
    }
}
