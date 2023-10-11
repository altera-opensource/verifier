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

package com.intel.bkp.command.messages.sigma;

import com.intel.bkp.crypto.constants.CryptoConstants;
import com.intel.bkp.crypto.exceptions.HMacProviderException;
import com.intel.bkp.crypto.hmac.IHMacProvider;
import com.intel.bkp.test.KeyGenUtils;
import com.intel.bkp.test.RandomUtils;
import com.intel.bkp.test.SigningUtils;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPair;
import java.security.Provider;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

@ExtendWith(MockitoExtension.class)
public class SigmaM3MessageBuilderTest {

    @Test
    public void build_ReturnValidObject() throws HMacProviderException {
        // given
        KeyPair ecKey = KeyGenUtils.genEc384();
        assert ecKey != null;
        byte[] mockSignature = SigningUtils.signEcData(
            "testData".getBytes(), ecKey.getPrivate(), CryptoConstants.SHA384_WITH_ECDSA
        );

        SigmaM3Message msg = new SigmaM3MessageBuilder()
            .sdmSessionId(RandomUtils.generateRandomBytes(4))
            .bkpsDhPubKey(RandomUtils.generateRandomBytes(SigmaM3MessageBuilder.DH_PUBLIC_KEY_LEN))
            .deviceDhPubKey(RandomUtils.generateRandomBytes(SigmaM3MessageBuilder.DH_PUBLIC_KEY_LEN))
            .signature(bytes -> mockSignature)
            .mac(new IHMacProvider() {
                @Override
                public Provider getProvider() {
                    return null;
                }

                @Override
                public byte[] getMasterKey() {
                    return new byte[0];
                }

                @Override
                public String getAlgorithmType() {
                    return null;
                }

                @Override
                public byte[] getHash(byte[] data) {
                    return RandomUtils.generateRandomBytes(SigmaM3MessageBuilder.MAC_LEN);
                }
            })
            .build();

        // when
        final byte[] result = msg.array();
        SigmaM3Message resultMessage = new SigmaM3MessageBuilder().parse(result).build();

        // then
        assertNotNull(result);
        assertNotNull(resultMessage);
        assertArrayEquals(msg.getBkpsDhPubKey(), resultMessage.getBkpsDhPubKey());
        assertArrayEquals(msg.getDeviceDhPubKey(), resultMessage.getDeviceDhPubKey());
        assertArrayEquals(msg.getSignature(), resultMessage.getSignature());
        assertArrayEquals(msg.getMac(), resultMessage.getMac());
    }
}
