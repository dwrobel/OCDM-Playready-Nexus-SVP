/*
 * Copyright 2017-2018 Metrological
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include "cdmi.h"
#include <core/core.h>
#include <vector>

#include <nexus_config.h>
#include <nxclient.h>
#include <nexus_platform.h>
#include <nexus_memory.h>
#include <bstd.h>           /* brcm includes */
#include <bkni.h>

#include <oemcommon.h>
#include <drmmanager.h>
#include <drmmathsafe.h>
#include <drmtypes.h>
#include <drmerr.h>

enum LogLevel {
    LERROR_ = 31,
    LWARNING_ = 33,
    LINFO_ = 32
};

#define LOGGER(lvl, fmt , ... )    \
        do{ \
            fprintf(stdout, "\033[1;%dm[%s:%d](%s){object=%p} " fmt "\n\033[0m", lvl, __FILE__, __LINE__, __FUNCTION__, this, ##__VA_ARGS__);    \
            fflush(stdout); \
        }while( 0 )

namespace CDMi {
struct PlayLevels {
    uint16_t compressedDigitalVideoLevel_;   //!< Compressed digital video output protection level.
    uint16_t uncompressedDigitalVideoLevel_; //!< Uncompressed digital video output protection level.
    uint16_t analogVideoLevel_;              //!< Analog video output protection level.
    uint16_t compressedDigitalAudioLevel_;   //!< Compressed digital audio output protection level.
    uint16_t uncompressedDigitalAudioLevel_; //!< Uncompressed digital audio output protection level.
};

class MediaKeySession : public IMediaKeySession, public IMediaKeySessionExt {
private:
    enum KeyState {
        // Has been initialized.
        KEY_INIT = 0,
        // Has a key message pending to be processed.
        KEY_PENDING = 1,
        // Has a usable key.
        KEY_READY = 2,
        // Has an error.
        KEY_ERROR = 3,
        // Has been closed.
        KEY_CLOSED = 4
    };
    enum MessageType {
        LicenseRequest = 0,
        LicenseRenewal = 1,
        LicenseRelease = 2,
        IndividualizationRequest = 3
    };
public:
    //static const std::vector<std::string> m_mimeTypes;

    MediaKeySession(const uint8_t *f_pbInitData, uint32_t f_cbInitData, const uint8_t *f_pbCDMData, uint32_t f_cbCDMData, DRM_VOID *f_pOEMContext);
    ~MediaKeySession();
    bool playreadyGenerateKeyRequest();
    bool ready() const { return m_eKeyState == KEY_READY; }

// MediaKeySession overrides
    virtual void Run(
        const IMediaKeySessionCallback *f_piMediaKeySessionCallback) override;

    virtual CDMi_RESULT Load() override;

    virtual void Update(
        const uint8_t *f_pbKeyMessageResponse,
        uint32_t f_cbKeyMessageResponse) override;

    virtual CDMi_RESULT Remove() override;

    virtual CDMi_RESULT Close(void) override;

    virtual const char *GetSessionId(void) const override;
    virtual const char *GetKeySystem(void) const override;
    virtual CDMi_RESULT Decrypt(
        const uint8_t *f_pbSessionKey,
        uint32_t f_cbSessionKey,
        const uint32_t *f_pdwSubSampleMapping,
        uint32_t f_cdwSubSampleMapping,
        const uint8_t *f_pbIV,
        uint32_t f_cbIV,
        const uint8_t *f_pbData,
        uint32_t f_cbData,
        uint32_t *f_pcbOpaqueClearContent,
        uint8_t **f_ppbOpaqueClearContent,
        const uint8_t keyIdLength,
        const uint8_t* keyId,
        bool initWithLast15) override;

    virtual CDMi_RESULT ReleaseClearContent(
        const uint8_t *f_pbSessionKey,
        uint32_t f_cbSessionKey,
        const uint32_t  f_cbClearContentOpaque,
        uint8_t  *f_pbClearContentOpaque ) override;

    virtual uint32_t GetSessionIdExt(void) const override;
    virtual CDMi_RESULT SetDrmHeader(const uint8_t drmHeader[], uint32_t drmHeaderLength) override;
    virtual CDMi_RESULT GetChallengeDataExt(uint8_t* challenge, uint32_t& challengeSize, uint32_t isLDL) override;
    virtual CDMi_RESULT CancelChallengeDataExt() override;
    virtual CDMi_RESULT StoreLicenseData(const uint8_t licenseData[], uint32_t licenseDataSize, uint8_t* secureStopId) override;
    virtual CDMi_RESULT InitDecryptContextByKid() override;
    virtual CDMi_RESULT CleanDecryptContext() override;

private:
    bool LoadRevocationList(const char *revListFile);

    static DRM_RESULT PolicyCallback(
            const DRM_VOID *f_pvOutputLevelsData,
            DRM_POLICY_CALLBACK_TYPE f_dwCallbackType,
            const DRM_KID *f_pKID,
            const DRM_LID *f_pLID,
            const DRM_VOID *f_pv);

    int InitSecureClock(DRM_APP_CONTEXT *pDrmAppCtx);

    std::vector<unsigned char> drmIdToVectorId(const DRM_ID *drmId);
    string vectorToHexString(const std::vector<uint8_t>& vec);

private:
    DRM_APP_CONTEXT *m_poAppContext;
    DRM_DECRYPT_CONTEXT *m_oDecryptContext; 
    DRM_BYTE *m_pbOpaqueBuffer;
    DRM_DWORD m_cbOpaqueBuffer;

    DRM_BYTE *m_pbRevocationBuffer;

    std::string m_customData;

    IMediaKeySessionCallback *m_piCallback;
    KeyState m_eKeyState;
    DRM_CHAR m_rgchSessionID[CCH_BASE64_EQUIV(sizeof(DRM_ID)) + 1];
    DRM_BOOL m_fCommit;
    DRM_VOID *m_pOEMContext;

    WPEFramework::Core::CriticalSection _decoderLock;

    std::vector<uint8_t> mDrmHeader;
    uint32_t m_SessionId;
    std::vector<uint8_t> mBatchId;
    std::vector<std::vector<uint8_t>>  mLicenseIds;
    std::vector<std::vector<uint8_t>>  mKeyIds;
    bool m_decryptInited;
};

} // namespace CDMi
