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

package com.intel.bkp.crypto.sigma;

import com.intel.bkp.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.crypto.exceptions.EcdhKeyPairException;
import com.intel.bkp.crypto.exceptions.HMacProviderException;
import com.intel.bkp.crypto.exceptions.KeystoreGenericException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class SigmaProviderTest {

    private final EcdhKeyPair serviceDhKeyPair = EcdhKeyPair.generate();
    private final EcdhKeyPair deviceDhKeyPair = EcdhKeyPair.generate();

    public SigmaProviderTest() throws EcdhKeyPairException {
    }

    @Test
    public void constructor_Success() {
        // when
        final SigmaProvider result = new SigmaProvider(serviceDhKeyPair, deviceDhKeyPair);

        // then
        Assertions.assertNotNull(result);
        Assertions.assertNotNull(result.getServiceDhKeyPair());
        Assertions.assertNotNull(result.getDeviceDhKeyPair());
    }

    @Test
    public void establishSigmaProtocol() throws EcdhKeyPairException, HMacProviderException, KeystoreGenericException {
        // given
        final SigmaProvider result = new SigmaProvider(serviceDhKeyPair, deviceDhKeyPair);

        // when
        result.establishSigmaProtocol();

        // then
        Assertions.assertNotNull(result.getPmk());
        Assertions.assertNotNull(result.getSek());
        Assertions.assertNotNull(result.getSmk());
    }
}
