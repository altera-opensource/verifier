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

package com.intel.bkp.verifier.config;

import com.intel.bkp.core.exceptions.JceSecurityProviderException;
import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.core.security.JceSecurityProvider;
import com.intel.bkp.core.security.SecurityProviderParams;
import com.intel.bkp.core.security.params.ProviderProperties;
import com.intel.bkp.verifier.exceptions.InternalLibraryException;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.lang.reflect.InvocationTargetException;
import java.security.Provider;
import java.security.Security;
import java.util.Optional;

@Slf4j
@NoArgsConstructor(access = AccessLevel.PRIVATE)
public class JceSecurityConfiguration {

    private static ISecurityProvider securityProvider = null;

    public static ISecurityProvider getSecurityProvider(SecurityProviderParams securityProviderParams) {
        if (securityProvider == null) {
            initializeJceProvider(getProviderClassName(securityProviderParams));

            securityProvider = new JceSecurityProvider(securityProviderParams,
                () -> KeystoreManagerChooser.choose(securityProviderParams.getProvider().getFileBased())
            );
        }
        return securityProvider;
    }

    private static String getProviderClassName(SecurityProviderParams params) {
        return Optional.ofNullable(params)
            .map(SecurityProviderParams::getProvider)
            .map(ProviderProperties::getClassName)
            .orElseThrow(() -> new InternalLibraryException("Provide security provider params in config"));
    }

    private static void initializeJceProvider(String name) {
        try {
            Security.addProvider((Provider)Class.forName(name).getConstructor().newInstance());
        } catch (InstantiationException | IllegalAccessException
            | InvocationTargetException | NoSuchMethodException | ClassNotFoundException e) {
            throw new JceSecurityProviderException("Failed to initialize security provider using class: " + name, e);
        }
    }
}
