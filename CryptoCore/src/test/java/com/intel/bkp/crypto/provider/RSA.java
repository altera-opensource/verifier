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

package com.intel.bkp.crypto.provider;

import org.bouncycastle.util.encoders.Hex;

import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class RSA extends KeyPairGeneratorSpi {
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
                        "30820122300d06092a864886f70d01010105000382010f003082010a02820101009159f332c4dcbf10f7cce3384bd"
                            + "6a551378e3bd3a99e2ccfdc359465261c32dcf42b5f41286e21260c5f26edf5fba5f51bfdaae9de0cab3a15"
                            + "86888328207680fc92c6a82436bec68770395264b63f4464344c3d5f3b0f16660b9c9955bd9b4437c4dc934"
                            + "beac556ebce8e361ddf094a7b0225cc39a6675f28b16fef4798d8cc9fe8f96172aa6c1f4244facf0be1194a"
                            + "29f243fdcad4eb55639ec4f3a89542e47ce0fe0c964ab8b52aef66f8767d23dc6a1adc33527fce0810a2b38"
                            + "b76d1000920ae742c37167741070b00feaf31ef938f81e4a50cb9850cc797b784ab3efadfa651a19e9beb20"
                            + "106e998adcaeb3758e17110d368d8920ffb47c7992bea2be370203010001";

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
                        "308204bd020100300d06092a864886f70d0101010500048204a7308204a302010002820101009159f332c4dcbf10f"
                            + "7cce3384bd6a551378e3bd3a99e2ccfdc359465261c32dcf42b5f41286e21260c5f26edf5fba5f51bfdaae9"
                            + "de0cab3a1586888328207680fc92c6a82436bec68770395264b63f4464344c3d5f3b0f16660b9c9955bd9b4"
                            + "437c4dc934beac556ebce8e361ddf094a7b0225cc39a6675f28b16fef4798d8cc9fe8f96172aa6c1f4244fa"
                            + "cf0be1194a29f243fdcad4eb55639ec4f3a89542e47ce0fe0c964ab8b52aef66f8767d23dc6a1adc33527fc"
                            + "e0810a2b38b76d1000920ae742c37167741070b00feaf31ef938f81e4a50cb9850cc797b784ab3efadfa651"
                            + "a19e9beb20106e998adcaeb3758e17110d368d8920ffb47c7992bea2be370203010001028201003b0f267f3"
                            + "9784c765389bfc58f231f3719f0c42463e62e65231fee350f4023f69d8bc5ff8eb2f8eb21d9c3d2aac15e94"
                            + "729426cf31f749d7a7096c0c86d071f6452a4a67e5970cfb53eae88faef6524cb2be813feaa2efa5753f409"
                            + "9193a9a8d246fec0439b3a20d8870fc5dc6d36a4e061f40467422461c674779a8eb1992f5276281142e5f34"
                            + "a4a725f3f86f8fc144b3fc759d71b20fe5417bb5ff578fd4b4f870982a1de2cbdb75c2a8ebc611937a52123"
                            + "37ad1bfa989f811a8de9dbff7f0a9fc59bf9b031fcad4e57a804dca0fb30719c1471d20ce8425848caaa524"
                            + "5a0db9203e2c7676534e0a3bb4ade0edd8c56af872b8b2868cf4602e36015f422e8902818100fd551f2f866"
                            + "88f0a6271782f6f71d786d12b57de73ff5aa19ce4974e9663028249971cc2c63bd31f620f33806b4fd55c00"
                            + "ce7af108f054ff9f73a39c044312cf73ba50c2b6210ff3684e107c83667519defcf78f1940f3978eebc41ae"
                            + "032de426b8b1e96421db1434fbf25572bf6f0e6ca17e2acbf956375b0aa5a74772b4dab0281810092e1c19d"
                            + "b9a8446dcad57d5023de6e1151f0b27af6967c204a6c8b455cce3d254e7869df08c289e3688bebff55edc65"
                            + "d5d530e59ea52ddb347795dbeb84b988fe19b6acb1a64d894972b4f258a9c2cc70d4ad8caf127a4fe3e4ee3"
                            + "bdc28efd39a1955859e58c28aaab7e1b67a2ace3ae636c1bec9c4935c9569901681e580da502818100fc747"
                            + "d9580de65ddb568da9a7af6fa0f92171d83c4192f1a6b1daa63589ee67b2c16f9446904694a97100b04e8ec"
                            + "2ff575a04f08311e3fb6561289730b14448494119235d8066ebce4af16e2de97960ee817342558c74f7933a"
                            + "664515c2795329fb58e0fb3679fa532ad8beaa91777cea68ad30bd008718b7138f2d7a9826fed0281804c9d"
                            + "97c9f712cf86d99b9cbf15c6ab713b65ab23bac66a3ec9b36ebe2297ad8b6d30204167a75a1795ec0e90e4b"
                            + "89f9509de0e0956d21cb4ac5ea1489f8747301e055ca24ec535b7e45681f55a24f6b269bb95f3ddf0c8fe99"
                            + "6fbb19bb87ac8cc83d4795b4c7f45a7a13d0a5b1542f7b427f1cddc1f3ea2b78915d0b7b7080c50281800dd"
                            + "0813b083cb5d8ef279cd9f50cc563ac3f4264aee2c967245a6a5bced1d6212fa58d9dfb68fecab12edf1bf2"
                            + "e9dd3ff493ae2736ff3033c8ae6d7b82a2489c7f30c2419820ffb49156772433d7e122982927f34789e4f74"
                            + "ae69e2adb998c34f90cbd5f6b84e8e8cfa2630fe07fb4c8c402db9cbcf2e0e354ceb8be557366fa";

                    return Hex.decode(publicKeyEncodedHexString);
                }
            }
        );
    }
}
