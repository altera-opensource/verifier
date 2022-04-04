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

package com.intel.bkp.core.security;

import com.intel.bkp.core.security.params.KeyTypesProperties;
import com.intel.bkp.core.security.params.ProviderProperties;
import com.intel.bkp.core.security.params.SecurityProperties;
import com.intel.bkp.core.security.params.crypto.AesProperties;
import com.intel.bkp.core.security.params.crypto.EcProperties;
import com.intel.bkp.core.security.params.crypto.RsaProperties;
import com.intel.bkp.crypto.constants.CryptoConstants;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;

@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class SecurityProviderParamsSetter {

    public static final String STATIC_BC_PROVIDER_NAME = "BC";
    public static final String STATIC_BC_PROVIDER_CLASS_NAME = "org.bouncycastle.jce.provider.BouncyCastleProvider";
    public static final String STATIC_BC_KEY_STORE_NAME = "uber";
    public static final String STATIC_BC_KEY_STORE_PASSWORD = "donotchange";
    public static final String STATIC_BC_INPUT_STREAM = "/tmp/bc-keystore-static.jks";

    public static SecurityProviderParams setDefaultSecurityProviderParams() {
        ProviderProperties providerProperties = new ProviderProperties();
        providerProperties.setName(STATIC_BC_PROVIDER_NAME);
        providerProperties.setFileBased(true);
        providerProperties.setClassName(STATIC_BC_PROVIDER_CLASS_NAME);

        SecurityProperties securityProperties = new SecurityProperties();
        securityProperties.setKeyStoreName(STATIC_BC_KEY_STORE_NAME);
        securityProperties.setPassword(STATIC_BC_KEY_STORE_PASSWORD);
        securityProperties.setInputStreamParam(STATIC_BC_INPUT_STREAM);

        RsaProperties rsaProperties = new RsaProperties();
        rsaProperties.setKeyName(CryptoConstants.RSA_KEY);
        rsaProperties.setKeySize(CryptoConstants.RSA_KEY_SIZE);
        rsaProperties.setCipherType(CryptoConstants.RSA_CIPHER_TYPE);
        rsaProperties.setSignatureAlgorithm(CryptoConstants.SHA384_WITH_RSA);

        AesProperties aesProperties = new AesProperties();
        aesProperties.setKeyName(CryptoConstants.AES_KEY);
        aesProperties.setKeySize(CryptoConstants.AES_KEY_SIZE);
        aesProperties.setCipherType(CryptoConstants.AES_CIPHER_TYPE);

        EcProperties ecProperties = new EcProperties();
        ecProperties.setKeyName(CryptoConstants.ECDSA_KEY);
        ecProperties.setCurveSpec384(CryptoConstants.EC_CURVE_SPEC_384);
        ecProperties.setCurveSpec256(CryptoConstants.EC_CURVE_SPEC_256);
        ecProperties.setSignatureAlgorithm(CryptoConstants.SHA384_WITH_ECDSA);

        KeyTypesProperties keyTypesProperties = new KeyTypesProperties();
        keyTypesProperties.setRsa(rsaProperties);
        keyTypesProperties.setAes(aesProperties);
        keyTypesProperties.setEc(ecProperties);

        SecurityProviderParams securityProviderParams = new SecurityProviderParams();
        securityProviderParams.setProvider(providerProperties);
        securityProviderParams.setSecurity(securityProperties);
        securityProviderParams.setKeyTypes(keyTypesProperties);

        return securityProviderParams;
    }
}
