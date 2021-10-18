# Verifier

Verifier is a Java library responsible for performing FPGA attestation. 
It is able to retrieve measurements (evidence) from the FPGA device and compare it with reference integrity manifest (RIM).
It also retrieves and validates signature and chain of certificates to confirm authenticity and integrity of the measurements.

Workload is a sample application that triggers Verifier's interface. 

During attestation, communication is done via Hard Processor System (HPS), thus a listening TCP server (FCS Server) must be enabled on HPS, which can be found [here](https://github.com/altera-opensource/fcs_server).

After FCS Server is up and running, note down the #HOST# (hostname or ip address of HPS) and #PORT# (of FCS Server).

# Related documentation reference

### HPS

[Stratix10](https://www.intel.com/content/www/us/en/programmable/documentation/fnt1471308293130.html)

[Agilex](https://www.intel.com/content/www/us/en/programmable/documentation/bmm1553539841763.html)

### Quartus Prime
[Stratix10](https://www.intel.com/content/www/us/en/programmable/documentation/ndq1483601370898.html)

[Agilex](https://www.intel.com/content/www/us/en/programmable/documentation/jix1627616846940.html)

# Prerequisites

1. Java 11

2. [FCS Server](https://github.com/altera-opensource/fcs_server) should be up and running on HPS, with TCP traffic enabled

3. Configure network for outgoing communication on port 443 (HTTPS) and TCP communication to #HOST#:#PORT# of the FCS Server

4. Prepare Product Owner Root Signing Key (`root_private.pem`), chain (`root.qky`) and `quartus_sign` tool must be available 
   to be used during initialization step. Below links to official Quartus Prime user guide:
   1. [Stratix10](https://www.intel.com/content/www/us/en/programmable/documentation/ndq1483601370898.html#qzz1616549507856)
   2. [Agilex](https://www.intel.com/content/www/us/en/programmable/documentation/jix1627616846940.html#qzz1616549507856)

5. (Recommended) Set up Java Cryptography Extension ([JCE](https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html)) Provider of your choice (Gemalto Luna SA HSM, nCipher etc.)
    (Default) Alternatively, built-in BouncyCastle ([link](https://bouncycastle.org/) and [repository](https://github.com/bcgit/bc-java)) library can be used with no additional configuration

6. Generate Reference Integrity Manifest (RIM) file for your board design using `quartus_pfg` tool
    
    `quartus_pfg -c "my_design.rbf" stratix10.rim`

# Quick setup

## Build and configure

Build and deploy project using gradle:

    ./gradlew clean build deploy

> **WARNING**
> Task **_deploy_** will overwrite the content of **out/** directory.

In command line set strong password to security provider in environment variable **env:VERIFIER_SECURITY_PROVIDER_PASSWORD**

    export VERIFIER_SECURITY_PROVIDER_PASSWORD=

Output libraries are located under **out/** directory together with Verifier's config file `config.properties`.

## First run

Run workload sample application (which is a fat jar already containing the Verifier lib) with basic arguments

    java -jar ./out/workload.jar -i "" -c HEALTH

The output during first run shall be the instruction how to configure the library with chosen security provider.
Edit the `config.properties` and use `quartus_sign` tool with private key `root_private.pem` and chain `root_chain.qky`
to sign the pubkey and complete the _first run_ process.

> **WARNING**
> By default BouncyCastle security provider is used. It creates a file in /tmp directory. This /tmp directory might be cleaned after machine reboot.
> Edit `security-provider-params.security.input-stream-param` in `config.properties` to change this directory.
> For enhanced security it is recommended to use a stronger security provider.

> **Note**
>
> This is only one-time operation. 
> Clear the `verifier-key-params.key-name` parameter from `config.properties` in case
> it has to be repeated or a new Signing Key must be created.  
 

## Run

After the library with security provider is configured run the workload sample app again, this time providing #HOST# and #PORT# of the FCS Server running on HPS.

### Run HEALTH check

The command will verify the connection and return the device id (chip id) of FPGA

    java -jar ./out/workload.jar -i "host:#HOST#; port:#PORT#" -c HEALTH

e.g.,

    java -jar ./out/workload.jar -i "host:localhost; port:50001" -c HEALTH

### \[Stratix10 only\] Create Attestation SubKey
   
Provide #PUF_TYPE# identifier and #CONTEXT# (hex string up to 28 bytes)

    java -jar ./out/workload.jar -i “host:#HOST#; port:#PORT#” -c CREATE --puf-type #PUF_TYPE# --context #CONTEXT#

where:

- PUF_TYPE is an integer identifier of enum:

    `0 - IID, 1 - INTEL, 2 - UDS_EFUSE, 3 - IIDUSER, 4 - INTEL_USER`

- CONTEXT is random hex value provided as seed to SDM FW and cached by Verifier, max 28 bytes length

e.g.,    

    java -jar ./out/workload.jar -i “host:localhost; port:50001” -c CREATE --puf-type 2 --context 01020304050607080A0B0C0D0E0F0F112233445566778899AABBCC

### Get device attestation
    
Provide #PATH# to generated .rim file: 

    java -jar ./out/workload.jar -i “host:#HOST#; port:#PORT#” -c GET --ref-measurement #PATH#

e.g.,

    java -jar ./out/workload.jar -i “host:localhost; port:50001” -c GET --ref-measurement ./stratix10.rim

## Security provider

Verifier uses an EC 384 private key which must be protected in a security provider.
Security provider is a choice of the user, however it must implement Java Cryptography Extension ([JCE](https://docs.oracle.com/en/java/javase/11/security/java-cryptography-architecture-jca-reference-guide.html)) interface.

### Built-in BouncyCastle

By default, built-in file-based BouncyCastle library is used. 
It creates a file in location specified in `config.properties` under `security-provider-params.security.input-stream-param` parameter.
The file is encrypted with the master key specified by user:
1. (recommended) either in environment variable **env:VERIFIER_SECURITY_PROVIDER_PASSWORD**
2. or in `config.properties` under `security-provider-params.security.password`

Other settings under `security-provider-params` are already filled in and are specific to BouncyCastle. 

### Other providers

For other providers, user must provide a path to the provider's jar to application classpath and update `config.properties`
with values specific for that provider.

Run the below command providing path to provider's jar:

**Linux**

    java -cp workload.jar:[PATH_TO_PROVIDER_JAR] com.intel.bkp.workload.WorkloadApp ...

**Windows**

    java -cp [PATH_TO_PROVIDER_JAR];workload.jar com.intel.bkp.workload.WorkloadApp ...

**Example**

    java -cp workload.jar:/opt/libs-ext/OtherSecurityProvider.jar com.intel.bkp.workload.WorkloadApp -i "host:localhost; port:50001" -c HEALTH

# Integrate as a library

Verifier can also be integrated in User’s sample workload application.
To do this, invoke a below command providing path to the library jar
file. The Workload from **out/** directory is not used in this case.
Verifier API is described in Attestation Software Architecture
Specification (SAS) and interface can be found 
in `Verifier/src/main/java/com/intel/bkp/verifier/interfaces/VerifierExchange.java`.

Linux:

    java -cp sample-app.jar:Verifier.jar com.example.SampleApp ...

Windows:

    java -cp "Verifier.jar;sample-app.jar" com.example.SampleApp ...

# Comparison to RIM file (Reference Integrity Manifest)

Verifier iterates over each block of RIM json file and checks whether
all expected data is present in response from device, i.e.:

-   in measurement response for Stratix10,

-   in measurement response and certificate chain for Agilex.

> **Note**
>
> In case of Stratix10 device, layer 1 measurement (FW CMF descriptor
> hash) cannot be trusted, therefore it is not parsed from response.
> Including this measurement block in RIM for S10 will always cause attestation to fail.

# Logs

Application logs are presented in the console output and saved to file:

    ./log/workload.%d{yyyy-MM-dd}.log

By default `INFO` level is set. To change it to more detailed add
parameter `--log-level` when running Workload:

    java workload.jar (…) --log-level TRACE

All possible options are presented when called without any parameters:

    OFF, ERROR, WARN, INFO, DEBUG, TRACE

# Configuration - config.properties

Configuration file `config.properties` contains parameters that will be parsed by Verifier, not the workload sample app.

|Parameter|Required|Description|Default/available options|Example|
| :--- | :---: | :--- | :---: | :--- |
| **GENERAL** |
| transport-layer-type| YES | Identifier of transport layer | HPS | |
| only-efuse-uds | NO | Option during Agilex attestation if the Verifier will try to retrieve both eFuse UDS chain and IID UDS chain from device. When set to true, the IID UDS chain will NOT be retrieved. | true, false (default) |
| **SQLite database** |
| database-configuration.internal-database | NO | If set to true, in-memory sqlite cache database will be created. If false, sqlite database will be stored in file <strong>verifier_core.sqlite</strong> in current folder. | true (default), false |
| **Verifier Signing Key** |
| verifier-key-params.verifier-root-qky-chain.single-chain-path | NO | Absolute path to Verifier Signing Key single root certificate chain for **Stratix10** in *.qky file (PSG format) - leave empty during first run or if you need rotate Verifier Signing Key. Can be empty if multi-chain-path is set. | - | /path/to/verifier_chain_single.qky |
| verifier-key-params.verifier-root-qky-chain.multi-chain-path | NO | Absolute path to Verifier Signing Key certificate chain for **Agilex** in *.qky file (PSG format) - leave empty during first run or if you need rotate Verifier Signing Key. Can be empty if single-chain-path is set. | - | /path/to/verifier_chain_multi.qky |
| verifier-key-params.key-name | NO | Verifier Signing Key alias used for identifying security object in Security Provider - leave empty during first run or if you need rotate Verifier Signing Key. | - | ced20836-8a55-49d5-862a-510296142a99 |
| **Certificate Distribution Point** |
| distribution-point.path-cer | YES | Path to certificate distribution point | - | https://tsci.intel.com/content/IPCS/certs/ |
| distribution-point.trusted-root-hash.s10 | NO | SHA256 fingerprint of trusted root certificate for Stratix10. To calculate, run: `openssl x509 -in s10_root.cer -noout -fingerprint -sha256` | - | 99B174476980A65FC581F499F60295B9DACA5E7DBAEEC25ECF3988049EC9ED5F |
| distribution-point.trusted-root-hash.dice | NO | SHA256 fingerprint of trusted root certificate (DICE) for Agilex. To calculate, run: `openssl x509 -in dice_root.cer -noout -fingerprint -sha256` | - | 35E08599DD52CB7533764DEE65C915BBAFD0E35E6252BCCD77F3A694390F618B |
| distribution-point.proxy-host | NO | Parameter to set proxy host if required. | - | proxy[.]company[.]com |
| distribution-point.proxy-port | NO | Parameter to set proxy port if required. | - | 911 |
| **Security provider** |  | __All settings are specific to used security provider.__ |
| security-provider-params.provider.name | YES | Security Provider name registered in system / available in Java classpath. | - | BC |
| security-provider-params.provider.file-based | YES | Set true if Security Provider is file based (eg.BouncyCastle), set false if HSM based (Luna, nCipher etc.) | - | true, false |
| security-provider-params.provider.class-name | YES | Security Provider canonical class name. | - | org.bouncycastle.jce.provider.BouncyCastleProvider |
| security-provider-params.security.key-store-name | YES | Name for keystore used to store data. | - | uber |
| security-provider-params.security.password | NO | Password for keystore. **For security, it is advised to set password with environment variable: __VERIFIER_SECURITY_PROVIDER_PASSWORD__** | - |  |
| security-provider-params.security.input-stream-param | YES | Keystore location. E.g., for BouncyCastle it is path to keystore file. For Gemalto Luna it would be slot number or partition name. | - | /tmp/bc-keystore-verifier.jks |
| security-provider-params.key-types.ec.key-name | YES | Class name for EC key. | - | EC |
| security-provider-params.key-types.ec.curve-spec-384 | YES | P-384 elliptic curve identifier. | - | secp256r1 |
| security-provider-params.key-types.ec.curve-spec-256 | YES | P-256 elliptic curve identifier. | - | secp384r1 |
| security-provider-params.key-types.ec.signature-algorithm | YES | SHA384 with ECDSA signature algorithm identifier. | - | SHA384withECDSA |
|  |  |  |  |

# Error Codes

Workload application possible return codes:

|Command|Integer|Error code|Description|
| :--- | :---: | :---: | :--- |
| HEALTH | 0 <br/> -1 | PASS <br/> ERROR | Health check success <br/> Health check failed |
| CREATE |  0 <br/> -1 | PASS <br/> ERROR | Operation successful <br/> Internal error occurred |
| GET |  0 <br/> -1 <br/> 1 | PASS <br/> ERROR <br/> FAIL | Attestation passed  <br/> Internal error occurred <br/> Attestation failed |
|  |  |  |  |

# Signing Key rotation

During first run or when Verifier Signing Key needs to be rotated, clear the `verifier-key-params.key-name` from `config.properties`.
In next run, a new key will be created, follow the instruction in the log to complete the process.

Additionally, you may clear the `verifier-key-params.verifier-root-qky-chain.single-chain-path` and `verifier-key-params.verifier-root-qky-chain.multi-chain-path`
parameters. If not cleared, during next run the existing files in those locations will be backed up with a new name:

    existing_chain.qky.backup_<timestamp_millis>_<random_hex_value>

e.g.,

    existing_chain.qky.backup_9918285401_AABBCCDD
