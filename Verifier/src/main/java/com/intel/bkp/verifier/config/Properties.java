/*
 * This project is licensed as below.
 *
 * **************************************************************************
 *
 * Copyright 2020-2021 Intel Corporation. All Rights Reserved.
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

public class Properties {

    public static final String TRANSPORT_LAYER_TYPE = "transport-layer-type";
    public static final String ONLY_EFUSE_UDS = "only-efuse-uds";
    public static final String DISTRIBUTION_POINT_GROUP = "distribution-point";
    public static final String TRUSTED_ROOT_HASH_GROUP = "trusted-root-hash";
    public static final String PROXY_GROUP = "proxy";
    public static final String PROVIDER_PARAMS_GROUP = "security-provider-params";
    public static final String VERIFIER_KEY_PARAMS_GROUP = "verifier-key-params";
    public static final String VERIFIER_KEY_CHAIN_GROUP = "verifier-root-qky-chain";
    public static final String DATABASE_CONFIGURATION_GROUP = "database-configuration";
    public static final String PROVIDER_GROUP = "provider";
    public static final String SECURITY_GROUP = "security";
    public static final String KEY_TYPES_GROUP = "key-types";
    public static final String EC_GROUP = "ec";

    public static final String DISTRIBUTION_POINT_PATH_CER = "path-cer";
    public static final String DISTRIBUTION_POINT_S10_TRUSTED_ROOT = "s10";
    public static final String DISTRIBUTION_POINT_DICE_TRUSTED_ROOT = "dice";
    public static final String DISTRIBUTION_POINT_PROXY_HOST = "host";
    public static final String DISTRIBUTION_POINT_PROXY_PORT = "port";

    public static final String VERIFIER_KEY_PARAMS_SINGLE_ROOT_QKY_CHAIN_PATH = "single-chain-path";
    public static final String VERIFIER_KEY_PARAMS_MULTI_ROOT_QKY_CHAIN_PATH = "multi-chain-path";
    public static final String VERIFIER_KEY_PARAMS_KEY_NAME = "key-name";
}
