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

package com.intel.bkp.core.security;

import com.intel.bkp.crypto.constants.SecurityKeyType;
import com.intel.bkp.crypto.interfaces.ISecurityProviderCommon;

import javax.crypto.SecretKey;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;

public interface ISecurityProvider extends ISecurityProviderCommon {

    Provider getProvider();

    IKeystoreManager getKeystoreManager();

    Object createSecurityObject(String name);

    Object createSecurityObject(SecurityKeyType keyType, String name);

    byte[] decryptRSA(String alias, byte[] encryptedData);

    SecretKey getKeyFromSecurityObject(String name);

    void importSecretKey(String name, SecretKey secretKey);

    void importEcKey(String name, PublicKey publicKey, PrivateKey privateKey);

    PrivateKey getPrivateKeyFromSecurityObject(String name);

    String getAesCipherType();
}
