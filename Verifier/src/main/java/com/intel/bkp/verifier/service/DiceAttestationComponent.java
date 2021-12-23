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

package com.intel.bkp.verifier.service;

import com.intel.bkp.ext.crypto.ecdh.EcdhKeyPair;
import com.intel.bkp.ext.crypto.exceptions.EcdhKeyPairException;
import com.intel.bkp.verifier.command.responses.attestation.GetMeasurementResponse;
import com.intel.bkp.verifier.command.responses.attestation.GetMeasurementResponseToTcbInfoMapper;
import com.intel.bkp.verifier.database.model.DiceRevocationCacheEntity;
import com.intel.bkp.verifier.exceptions.InternalLibraryException;
import com.intel.bkp.verifier.interfaces.CommandLayer;
import com.intel.bkp.verifier.interfaces.TransportLayer;
import com.intel.bkp.verifier.model.CertificateRequestType;
import com.intel.bkp.verifier.model.RootChainType;
import com.intel.bkp.verifier.model.VerifierExchangeResponse;
import com.intel.bkp.verifier.model.dice.DiceEnrollmentParamsParser;
import com.intel.bkp.verifier.model.dice.DiceParams;
import com.intel.bkp.verifier.model.dice.DiceParamsIssuerParser;
import com.intel.bkp.verifier.model.dice.TcbInfoAggregator;
import com.intel.bkp.verifier.model.dice.TcbInfoExtensionParser;
import com.intel.bkp.verifier.model.dice.UeidExtensionParser;
import com.intel.bkp.verifier.service.certificate.AppContext;
import com.intel.bkp.verifier.service.certificate.DiceAttestationRevocationService;
import com.intel.bkp.verifier.service.measurements.EvidenceVerifier;
import com.intel.bkp.verifier.service.sender.GetCertificateMessageSender;
import com.intel.bkp.verifier.service.sender.GetMeasurementMessageSender;
import com.intel.bkp.verifier.service.sender.TeardownMessageSender;
import com.intel.bkp.verifier.sigma.GetMeasurementVerifier;
import com.intel.bkp.verifier.sigma.SigmaM2DeviceIdVerifier;
import com.intel.bkp.verifier.x509.X509CertificateParser;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.security.cert.X509Certificate;
import java.util.Optional;

import static com.intel.bkp.ext.core.manufacturing.model.AttFamily.AGILEX;
import static com.intel.bkp.ext.utils.HexConverter.toHex;
import static com.intel.bkp.verifier.model.CertificateRequestType.DEVICE_ID_ENROLLMENT;
import static com.intel.bkp.verifier.model.CertificateRequestType.UDS_EFUSE_ALIAS;
import static com.intel.bkp.verifier.model.CertificateRequestType.UDS_IID_PUF_ALIAS;
import static com.intel.bkp.verifier.model.DiceRevocationStatus.REVOKED;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PACKAGE)
@NoArgsConstructor
public class DiceAttestationComponent {

    private final GetMeasurementResponseToTcbInfoMapper measurementMapper = new GetMeasurementResponseToTcbInfoMapper();
    private GetCertificateMessageSender getCertificateMessageSender = new GetCertificateMessageSender();
    private X509CertificateParser certificateParser = new X509CertificateParser();
    private DiceAttestationRevocationService diceAttestationRevocationService = new DiceAttestationRevocationService();
    private DiceParamsIssuerParser diceParamsIssuerParser = new DiceParamsIssuerParser();
    private DiceEnrollmentParamsParser diceEnrollmentParamsParser = new DiceEnrollmentParamsParser();
    private UeidExtensionParser ueidExtensionParser = new UeidExtensionParser();
    private TcbInfoExtensionParser tcbInfoExtensionParser = new TcbInfoExtensionParser();
    private GetMeasurementMessageSender getMeasurementMessageSender = new GetMeasurementMessageSender();
    private TeardownMessageSender teardownMessageSender = new TeardownMessageSender();
    private GetMeasurementVerifier getMeasurementVerifier = new GetMeasurementVerifier();
    private EvidenceVerifier evidenceVerifier = new EvidenceVerifier();
    private SigmaM2DeviceIdVerifier deviceIdVerifier = new SigmaM2DeviceIdVerifier();
    private TcbInfoAggregator tcbInfoAggregator = new TcbInfoAggregator();

    public VerifierExchangeResponse perform(byte[] firmwareCertificateResponse, String refMeasurement,
                                            byte[] deviceId) {
        return perform(AppContext.instance(), firmwareCertificateResponse, refMeasurement, deviceId);
    }

    VerifierExchangeResponse perform(AppContext appContext, byte[] firmwareCertificateResponse, String refMeasurement,
                                     byte[] deviceId) {

        diceAttestationRevocationService.withDeviceId(deviceId);

        final TransportLayer transportLayer = appContext.getTransportLayer();
        final CommandLayer commandLayer = appContext.getCommandLayer();
        final X509Certificate aliasX509 = getNextCert(transportLayer, commandLayer, UDS_EFUSE_ALIAS);
        parseTcbInfoAndAddToChain(aliasX509);

        final X509Certificate firmwareX509 = certificateParser.toX509(firmwareCertificateResponse);
        final DiceParams diceParams = diceParamsIssuerParser.parse(firmwareX509);
        ueidExtensionParser.parse(firmwareX509);
        parseTcbInfoAndAddToChain(firmwareX509);

        Optional<X509Certificate> deviceIdCert = Optional.empty();

        if (!isRevoked(appContext, deviceId)) {
            deviceIdCert = diceAttestationRevocationService.fmGetDeviceIdCert(diceParams);
        }

        deviceIdCert.ifPresentOrElse(this::parseTcbInfoAndAddToChain,
            () -> runEnrollmentCertFlow(appContext, deviceId, transportLayer, commandLayer)
        );

        if (isIidAliasFlow(appContext)) {
            diceAttestationRevocationService.addIid(getNextCert(transportLayer, commandLayer, UDS_IID_PUF_ALIAS));

            diceAttestationRevocationService
                .fmGetIidUdsCert(diceParams)
                .ifPresentOrElse(diceAttestationRevocationService::addIid,
                    () -> {
                        throw new InternalLibraryException("IID UDS certificate not found on Distribution Point.");
                    }
                );
        }

        diceAttestationRevocationService.verifyChains();

        final EcdhKeyPair serviceDhKeyPair = generateEcdhKeyPair();
        final GetMeasurementResponse response =
            getMeasurementMessageSender
                .withChainType(RootChainType.MULTI)
                .send(transportLayer, commandLayer, serviceDhKeyPair);
        getMeasurementVerifier.verify(aliasX509.getPublicKey(), response, serviceDhKeyPair);

        deviceIdVerifier.verify(deviceId, response.getDeviceUniqueId());
        teardownMessageSender.send(transportLayer, commandLayer, response.getSdmSessionId());

        tcbInfoAggregator.add(measurementMapper.map(response));
        tcbInfoAggregator.add(tcbInfoExtensionParser.getTcbInfos());

        return evidenceVerifier.verify(tcbInfoAggregator, refMeasurement);
    }

    private void parseTcbInfoAndAddToChain(X509Certificate certificate) {
        tcbInfoExtensionParser.parse(certificate);
        diceAttestationRevocationService.add(certificate);
    }

    private X509Certificate getNextCert(TransportLayer transportLayer, CommandLayer commandLayer,
                                        CertificateRequestType certType) {
        return certificateParser.toX509(getCertificateMessageSender.send(transportLayer, commandLayer, certType));
    }

    private void runEnrollmentCertFlow(AppContext appContext, byte[] deviceId, TransportLayer transportLayer,
                                       CommandLayer commandLayer) {

        log.debug("DeviceID cert not found on Distribution Point.");
        final X509Certificate enrollmentX509 = getNextCert(transportLayer, commandLayer, DEVICE_ID_ENROLLMENT);
        parseTcbInfoAndAddToChain(enrollmentX509);

        final Optional<X509Certificate> ipcsEnrollmentCert = diceAttestationRevocationService.fmGetEnrollmentCert(
            diceEnrollmentParamsParser.parse(enrollmentX509));

        ipcsEnrollmentCert.ifPresentOrElse(this::parseTcbInfoAndAddToChain,
            () -> {
                throw new InternalLibraryException("IPCS Enrollment certificate not found on Distribution Point.");
            }
        );

        createRevokedEntityInDatabase(appContext, deviceId);
    }

    private boolean isRevoked(AppContext appContext, byte[] deviceId) {
        return readEntityFromDatabase(appContext, deviceId)
            .map(DiceRevocationCacheEntity::isRevoked)
            .orElse(false);
    }

    private boolean isIidAliasFlow(AppContext appContext) {
        return isAgilex() && !appContext.getLibConfig().getAttestationCertificateFlow().isOnlyEfuseUds();
    }

    private boolean isAgilex() {
        return AGILEX.getFamilyId() == ueidExtensionParser.getUeidExtension().getFamilyId();
    }

    private Optional<DiceRevocationCacheEntity> readEntityFromDatabase(AppContext appContext, byte[] deviceId) {
        return appContext
            .getSqLiteHelper()
            .getDiceRevocationCacheEntityService()
            .read(deviceId);
    }

    private void createRevokedEntityInDatabase(AppContext appContext, byte[] deviceId) {
        appContext
            .getSqLiteHelper()
            .getDiceRevocationCacheEntityService()
            .store(
                new DiceRevocationCacheEntity(toHex(deviceId), REVOKED)
            );
    }

    private EcdhKeyPair generateEcdhKeyPair() {
        try {
            return EcdhKeyPair.generate();
        } catch (EcdhKeyPairException e) {
            throw new InternalLibraryException("Failed to generate ECDH keypair.", e);
        }
    }
}
