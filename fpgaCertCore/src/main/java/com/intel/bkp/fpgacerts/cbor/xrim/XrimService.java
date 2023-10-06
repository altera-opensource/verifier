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

package com.intel.bkp.fpgacerts.cbor.xrim;

import com.intel.bkp.fpgacerts.cbor.CborBroker;
import com.intel.bkp.fpgacerts.cbor.CborConverter;
import com.intel.bkp.fpgacerts.cbor.CborObjectParser;
import com.intel.bkp.fpgacerts.cbor.LocatorType;
import com.intel.bkp.fpgacerts.cbor.exception.XrimVerificationException;
import com.intel.bkp.fpgacerts.cbor.rim.RimUnsigned;
import com.intel.bkp.fpgacerts.cbor.signer.CborSignatureVerifier;
import com.intel.bkp.fpgacerts.cbor.xrim.parser.XrimSignedParser;
import com.intel.bkp.fpgacerts.cbor.xrim.parser.XrimUnsignedParser;
import com.intel.bkp.fpgacerts.dp.DistributionPointConnector;
import com.intel.bkp.fpgacerts.url.FetchDataSchemeBroker;
import com.intel.bkp.fpgacerts.utils.VerificationStatusLogger;
import com.upokecenter.cbor.CBORObject;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.PublicKey;
import java.util.Optional;

import static com.intel.bkp.fpgacerts.cbor.CborConverter.XRIM_SIGNED;
import static com.intel.bkp.fpgacerts.cbor.CborConverter.XRIM_UNSIGNED;

@RequiredArgsConstructor
@Slf4j
public class XrimService {

    private final DistributionPointConnector dpConnector;
    private final CborSignatureVerifier cborSignatureVerifier;

    public void verifyXRimAndEnsureRimIsNotRevoked(RimUnsigned coRim, PublicKey rimSigPubkey, boolean acceptUnsigned) {
        log.info("Verifying XCoRIM with accept unsigned flag set to: {}", acceptUnsigned);
        findXCoRimUrl(coRim)
            .ifPresentOrElse(
                url -> handlePresentLocator(coRim, rimSigPubkey, acceptUnsigned, url),
                () -> handleEmptyLocator(acceptUnsigned)
            );
    }

    private void handlePresentLocator(RimUnsigned coRim, PublicKey rimSigPubkey, boolean acceptUnsigned, String url) {
        log.info("Downloading XCoRIM data from: {}", url);
        final var xCorRimCbor = downloadXCoRim(url);
        final var xCoRimUnsigned = getValidStructure(rimSigPubkey, xCorRimCbor, acceptUnsigned);
        verifyCoRimIsNotRevokedOnXCoRim(coRim, xCoRimUnsigned);
    }

    private static void handleEmptyLocator(boolean acceptUnsigned) {
        if (!acceptUnsigned) {
            throw new XrimVerificationException("unable to find XCoRIM locator in provided CoRIM file.");
        } else {
            log.info(VerificationStatusLogger.skipped("CER locator not found. Verification of XCoRIM"));
        }
    }

    private XrimUnsigned getValidStructure(PublicKey rimSigPubkey, CBORObject cbor, boolean acceptUnsigned) {
        final CborConverter cborConverter = CborBroker.detectCborType(cbor);
        return switch (cborConverter) {
            case XRIM_SIGNED -> handleSigned(rimSigPubkey, cbor);
            case XRIM_UNSIGNED -> handleUnsigned(cbor, acceptUnsigned);
            default -> throw new XrimVerificationException("not a XCoRIM object.");
        };
    }

    private static XrimUnsigned handleUnsigned(CBORObject cbor, boolean acceptUnsigned) {
        if (acceptUnsigned) {
            return ((XrimUnsignedParser) XRIM_UNSIGNED.getParser()).parse(cbor);
        } else {
            throw new XrimVerificationException("XCoRIM not signed. Signature cannot be verified.");
        }
    }

    private XrimUnsigned handleSigned(PublicKey rimSigPubkey, CBORObject cbor) {
        final var signed = ((XrimSignedParser) XRIM_SIGNED.getParser()).parse(cbor);
        verifySignature(cbor, rimSigPubkey);
        return signed.getPayload();
    }

    private Optional<String> findXCoRimUrl(RimUnsigned unsignedRim) {
        return unsignedRim.getLocatorLink(LocatorType.XCORIM);
    }

    private CBORObject downloadXCoRim(String url) {
        return FetchDataSchemeBroker.fetchData(url, dpConnector)
            .map(content -> CborObjectParser.instance().parse(content))
            .orElseThrow(
                () -> new XrimVerificationException("unable to download or parse XCoRIM from path: %s".formatted(url))
            );
    }

    private void verifySignature(CBORObject signedXCoRim, PublicKey sigPubKey) {
        Optional.ofNullable(sigPubKey)
            .filter(pubKey -> cborSignatureVerifier.verify(pubKey, signedXCoRim))
            .orElseThrow(() -> new XrimVerificationException("invalid signature."));
        log.info(VerificationStatusLogger.success("Verified XCoRIM signature"));
    }

    private void verifyCoRimIsNotRevokedOnXCoRim(RimUnsigned coRim, XrimUnsigned xrimUnsigned) {
        final boolean revoked = xrimUnsigned.getDenyList().contains(coRim.getManifestId());
        if (revoked) {
            throw new XrimVerificationException("provided CoRIM is revoked.");
        }
        log.info(VerificationStatusLogger.success("Verified CoRIM revocation status"));
    }
}
