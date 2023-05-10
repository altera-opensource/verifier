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

package com.intel.bkp.verifier.command.messages.subkey;

import com.intel.bkp.core.security.ISecurityProvider;
import com.intel.bkp.crypto.constants.SecurityKeyType;
import com.intel.bkp.crypto.pem.PemFormatEncoder;
import com.intel.bkp.crypto.pem.PemFormatHeader;
import com.intel.bkp.verifier.command.messages.VerifierRootChainManager;
import com.intel.bkp.verifier.exceptions.InternalLibraryException;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;

import static com.intel.bkp.verifier.config.Properties.VERIFIER_KEY_CHAIN_GROUP;
import static com.intel.bkp.verifier.config.Properties.VERIFIER_KEY_PARAMS_GROUP;
import static com.intel.bkp.verifier.config.Properties.VERIFIER_KEY_PARAMS_KEY_NAME;
import static com.intel.bkp.verifier.config.Properties.VERIFIER_KEY_PARAMS_MULTI_ROOT_QKY_CHAIN_PATH;
import static com.intel.bkp.verifier.config.Properties.VERIFIER_KEY_PARAMS_SINGLE_ROOT_QKY_CHAIN_PATH;

@Slf4j
@RequiredArgsConstructor
@AllArgsConstructor
public class VerifierKeyManager {

    private final ISecurityProvider securityService;
    @Getter
    private final String verifierKeyName;
    private GuidProvider guidProvider = new GuidProvider();
    private VerifierRootChainManager verifierRootChainManager = new VerifierRootChainManager();

    public boolean initialized() {
        if (StringUtils.isBlank(verifierKeyName)) {
            return false;
        }

        if (!securityService.existsSecurityObject(verifierKeyName)) {
            throw new IllegalArgumentException(
                String.format("Provided key does not exist in security enclave: %s. "
                        + "Please remove the key name from config and call the healthCheck API to create a new key.",
                    verifierKeyName));
        }

        return true;
    }

    public void initialize() {
        createNewKey();
    }

    private void createNewKey() {
        verifierRootChainManager.backupExistingChainFile();

        final String guid = guidProvider.generateNewGuid();
        createKeyInSecurityEnclave(guid);
        returnGuidAndPubKeyInPem(guid);
    }

    private void createKeyInSecurityEnclave(String guid) {
        securityService.createSecurityObject(SecurityKeyType.EC, guid);
        if (!securityService.existsSecurityObject(guid)) {
            throw new InternalLibraryException("Failed to create new Verifier Signing Key in security enclave.");
        }
    }

    private void returnGuidAndPubKeyInPem(String guid) {
        final byte[] pubKey = securityService.getPubKeyFromSecurityObject(guid);

        log.info("New Verifier Signing Key was successfully created in security enclave. Perform below steps:"
                + "\n   1. Paste new Verifier key name into the configuration file:"
                + "\n      {}={}"
                + "\n   2. Save the Verifier public key as PEM file (verifier_pub.pem):\n{}"
                + "\n   3. Sign the public key to generate the chain (verifier_chain.qky) using Product Owner "
                + "Root Signing Key with Quartus Sign tool and set the Attestation permission. "
                + "\n      -- example command for Stratix10 - single root chain: "
                + "\n          quartus_sign --family=stratix10 --operation=APPEND_KEY "
                + "--previous_pem=root_private.pem --previous_qky=root.qky --permission=512 --cancel=0 "
                + "verifier_pub.pem verifier_chain_single.qky"
                + "\n      -- example command for Agilex - multi root chain: "
                + "\n          quartus_sign --family=agilex --operation=APPEND_KEY "
                + "--previous_pem=root_private_chain.pem --previous_qky=root_multi.qky --permission=512 --cancel=0 "
                + "verifier_pub.pem verifier_chain_multi.qky"
                + "\n   4. Provide absolute path to these chains into the configuration file:"
                + "\n      -- single root chain:"
                + "\n      {}=<ABSOLUTE_PATH>/verifier_chain_single.qky\n"
                + "\n      -- multi root chain:"
                + "\n      {}=<ABSOLUTE_PATH>/verifier_chain_multi.qky\n",
            String.join(".", VERIFIER_KEY_PARAMS_GROUP, VERIFIER_KEY_PARAMS_KEY_NAME), guid,
            PemFormatEncoder.encode(PemFormatHeader.PUBLIC_KEY, pubKey),
            String.join(".", VERIFIER_KEY_PARAMS_GROUP, VERIFIER_KEY_CHAIN_GROUP,
                VERIFIER_KEY_PARAMS_SINGLE_ROOT_QKY_CHAIN_PATH),
            String.join(".", VERIFIER_KEY_PARAMS_GROUP, VERIFIER_KEY_CHAIN_GROUP,
                VERIFIER_KEY_PARAMS_MULTI_ROOT_QKY_CHAIN_PATH)
        );
    }
}
