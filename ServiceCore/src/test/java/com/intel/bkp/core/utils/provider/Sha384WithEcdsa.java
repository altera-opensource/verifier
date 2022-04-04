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

package com.intel.bkp.core.utils.provider;

import org.bouncycastle.util.encoders.Hex;

import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

public class Sha384WithEcdsa extends SignatureSpi {
    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {

    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey == null) {
            throw new InvalidKeyException();
        }
    }

    private byte[] data = null;

    @Override
    protected void engineUpdate(byte b) throws SignatureException {

    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        data = b;
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if ((new String(data)).equals("error_content")) {
            throw new SignatureException();
        } else {
            String certificateHexString =
                "3082052a30820312020900c490d63e50e7b094300d06092a864886f70d01010b05003055310b300906035504061302504c3113"
                    + "301106035504080c0a536f6d652d5374617465310c300a060355040a0c03496e74310c300a060355040b0c03496e7431"
                    + "15301306035504030c0c524f4f542054455354204341301e170d3138303631383036333231345a170d32383036313530"
                    + "36333231345a3059310b300906035504061302504c310c300a06035504080c03496e74310c300a06035504070c03496e"
                    + "74310c300a060355040a0c03496e74310c300a060355040b0c03496e743112301006035504030c0954455354204c4541"
                    + "4630820222300d06092a864886f70d01010105000382020f003082020a0282020100c2ea57caee71e8b67a1b2436d3e9"
                    + "12ac8efc6239f655b72757aefd04a4c1bf37d591ed57ec2ad64de94fc991bab2613ae974b55a51187533b27de99cb35d"
                    + "e78a761f4453d8996dc2ea2e3f4c4dda7f2cff16fa46624a7e3019b13b7dace3143db0525d0c148791de694dc42a2578"
                    + "2039bc6e2a721c5434a7d4e29ec8e8908ae3fbbf3750eed07a0f32099b06d228718d0455a2c6de60879e0b37e5dd8b0f"
                    + "18b75dc934bee3671dcba1412fcda5d268ab562feb46f05aca202bfe4c89c7921e212cf810b23a8256ef15629ef13f00"
                    + "3159d519ac69d390473763aef24672f961e5ceb34fd8033207fc0653843b97b32f8625c3d2545abe1916948ac24119a8"
                    + "89988d8979a67c879a170c909bc1a5608811f987b2bbe8296a0980861c32be19404d9f2a4504044bc0a371b5ed212d62"
                    + "a531a1c95434aebf6efb59704c302ca81ad2d12ef678bc89390ae7b43728938a7cce19edf8287ac8707e44162057f517"
                    + "33affafc1a1bb03e71b24fbfa3edfc3ac5a87439b8246ca93762f3098b387ef53a63193e0b9111956aad60fb550d991b"
                    + "fd44888bcfc41a315fc0c6c323331ce73ad8c251ba21d64af3f709d3eae7d61c183e1ed7e27af6705cb8be9e246a7e40"
                    + "2801265c05fdadfd45a40ecd8e517e4bd2aa9af00d079c98eab7e1ad467506555e45cbddb478a055b8e4aec159375215"
                    + "cf4936535eefe4555a913460a8a0248e84a90203010001300d06092a864886f70d01010b050003820201003cc980fc0a"
                    + "f5020aa92bb838847600fb6b12e13d0cd68e7521e2965d9461f755213ad9a86834692b226f1171801e83e83cbe308ba2"
                    + "592bf8d58dc5df1ba084d4f695179233216947e9dcabcae30c4f096e6da38275820ddaedb6e6ea7adce652b16e77abab"
                    + "5e8b2957c96e6296adee0bf4d55b41226bc834dd6386d8b5c0f74ca00583831137e9eabdbcb28025304085c28776f86b"
                    + "223fba669e4e0e30c311357504fcbce1dc366f7b8bcaf28abf54b84db9b498fb02f4407adc9df274c819855afcc1f081"
                    + "4fd8a9903c316ce41fe8b40a1434dc80bdb93480c2d612ca6c1177a9486fc2b5d370d3c49fb90c22bb32de64ac8b1012"
                    + "50da212fb611c4feb95e180bcf33678dd1dc53cd009cf2b93f45c913765462ecc187c72f81be901387ff4347b4638872"
                    + "faba808c9771a0ade94b92ec3c28f4194bfef009851bdf761bfa9593cf4a4223e3645cca60f183567b98433708867384"
                    + "010af721cb1adf5692746c778b7c9441eb698f2e7678af2e0967eeca82d251f8356d1bd229c73d6ac9fe574121f1a22f"
                    + "b2951464e1625580c684063da9b0d7a8783122dee3fb844983855c9635dd7388925aaee148c642437d69b7e0f2c981df"
                    + "a21336e43281d87a445110c2033240f1571707235c81055bcc33c6251c0b3a3529411dfe46ffbbae88bc063606fab7fa"
                    + "378bfd0a8a4cd2451817e632b0ba7edba4e509d31359b209484085";

            return Hex.decode(certificateHexString);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return false;
    }

    @Override
    @SuppressWarnings("deprecation")
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {

    }

    @Override
    @SuppressWarnings("deprecation")
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return null;
    }
}
