#include "MediaSession.h"

#include <drmbytemanip.h>
#include <drmsecurestoptypes.h>

#include <iostream>
#include <stdio.h>
#include <sstream>

using SafeCriticalSection = WPEFramework::Core::SafeSyncType<WPEFramework::Core::CriticalSection>;
extern WPEFramework::Core::CriticalSection drmAppContextMutex_;

// The rights we want to request.
const DRM_WCHAR PLAY[] = { DRM_ONE_WCHAR('P', '\0'),
                           DRM_ONE_WCHAR('l', '\0'),
                           DRM_ONE_WCHAR('a', '\0'),
                           DRM_ONE_WCHAR('y', '\0'),
                           DRM_ONE_WCHAR('\0', '\0')
};
const DRM_CONST_STRING PLAY_RIGHT = DRM_CREATE_DRM_STRING(PLAY);
const DRM_CONST_STRING* RIGHTS[] = { &PLAY_RIGHT };

namespace CDMi {

struct CallbackInfo
{
    IMediaKeySessionCallback * _callback;
    uint16_t _compressedVideo;
    uint16_t _uncompressedVideo;
    uint16_t _analogVideo;
    uint16_t _compressedAudio;
    uint16_t _uncompressedAudio;
};

static void * PlayLevelUpdateCallback(void * data)
{
    CallbackInfo * callbackInfo = static_cast<CallbackInfo *>(data);

    std::stringstream keyMessage;
    keyMessage << "{";
    keyMessage << "\"compressed-video\": " << callbackInfo->_compressedVideo << ",";
    keyMessage << "\"uncompressed-video\": " << callbackInfo->_uncompressedVideo << ",";
    keyMessage << "\"analog-video\": " << callbackInfo->_analogVideo << ",";
    keyMessage << "\"compressed-audio\": " << callbackInfo->_compressedAudio << ",";
    keyMessage << "\"uncompressed-audio\": " << callbackInfo->_uncompressedAudio;
    keyMessage << "}";

    std::string keyMessageStr = keyMessage.str();
    const uint8_t * messageBytes = reinterpret_cast<const uint8_t *>(keyMessageStr.c_str());

    char urlBuffer[64];
    strcpy(urlBuffer, "properties");
    callbackInfo->_callback->OnKeyMessage(messageBytes, keyMessageStr.length() + 1, urlBuffer);

    delete callbackInfo;
    return nullptr;
}

static DRM_RESULT opencdm_output_levels_callback(
    const DRM_VOID *outputLevels, 
    DRM_POLICY_CALLBACK_TYPE callbackType,    
    const DRM_KID */*f_pKID*/,
    const DRM_LID */*f_pLID*/,
    const DRM_VOID *data) {
    // We only care about the play callback.
    if (callbackType != DRM_PLAY_OPL_CALLBACK)
        return DRM_SUCCESS;

    const IMediaKeySessionCallback * constSessionCallback = reinterpret_cast<const IMediaKeySessionCallback *>(data);
    if (constSessionCallback != nullptr) {
        CallbackInfo * callbackInfo = new CallbackInfo;
        callbackInfo->_callback = const_cast<IMediaKeySessionCallback *>(constSessionCallback);

        // Pull out the protection levels.
        const DRM_PLAY_OPL_EX* playLevels = static_cast<const DRM_PLAY_OPL_EX*>(outputLevels);
        callbackInfo->_compressedVideo = playLevels->minOPL.wCompressedDigitalVideo;
        callbackInfo->_uncompressedVideo = playLevels->minOPL.wUncompressedDigitalVideo;
        callbackInfo->_analogVideo = playLevels->minOPL.wAnalogVideo;
        callbackInfo->_compressedAudio = playLevels->minOPL.wCompressedDigitalAudio;
        callbackInfo->_uncompressedAudio = playLevels->minOPL.wUncompressedDigitalAudio;

        // Run on a new thread, so we don't go too deep in the IPC callstack.
        pthread_t threadId;
        pthread_create(&threadId, nullptr, PlayLevelUpdateCallback, callbackInfo);

    }
    // All done.
    return DRM_SUCCESS;
}

uint32_t MediaKeySession::GetSessionIdExt() const
{    
    return m_SessionId;
}

CDMi_RESULT MediaKeySession::SetDrmHeader(const uint8_t drmHeader[], uint32_t drmHeaderLength)
{
    mDrmHeader.resize(drmHeaderLength);
    memcpy(&mDrmHeader[0], drmHeader, drmHeaderLength);
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::StoreLicenseData(const uint8_t licenseData[], uint32_t licenseDataSize, uint8_t * secureStopId)
{
    // open scope for DRM_APP_CONTEXT mutex
    SafeCriticalSection systemLock(drmAppContextMutex_);

    //const std::string licStr(licenseData.begin(), licenseData.end());
    //MYTRACE("\n%s", licStr.c_str());

    // === Store the license and check for license processing errors.
    //
    // NOTE: Drm_LicenseAcq_ProcessResponse() is the PR3 API that creates a
    // secure stop. There is one secure stop per license response, regardless of
    // how many licenses are in the response data.
    //
    DRM_LICENSE_RESPONSE drmLicenseResponse;
    // MUST zero the input DRM_LICENSE_RESPONSE struct!
    ZEROMEM(&drmLicenseResponse, sizeof(DRM_LICENSE_RESPONSE));
    DRM_RESULT err;
    // Non-persistent licenses (the kind in use) have no signature, so the
    // LIC_RESPONSE_SIGNATURE_NOT_REQUIRED flag must be used.
    err = Drm_LicenseAcq_ProcessResponse(
            m_poAppContext,
            DRM_PROCESS_LIC_RESPONSE_SIGNATURE_NOT_REQUIRED,
            &licenseData[0],
            (DRM_DWORD)licenseDataSize,
            &drmLicenseResponse);

    // First, check the return code of Drm_LicenseAcq_ProcessResponse()
    if (err ==  DRM_E_LICACQ_TOO_MANY_LICENSES) {
        // This means the server response contained more licenses than
        // DRM_MAX_LICENSE_ACK (usually 20). Should allocate space and retry.
        // FIXME NRDLIB-4481: This will need to be implemented when we start
        // using batch license requests.
        LOGGER(LERROR_, "Drm_LicenseAcq_ProcessResponse too many licenses in response.");
        return CDMi_S_FALSE;
    }
    else if (DRM_FAILED(err)) {
        LOGGER(LERROR_, "Drm_LicenseAcq_ProcessResponse failed (error: 0x%08X)", static_cast<unsigned int>(err));
        return CDMi_S_FALSE;
    }

    // Next, examine the returned drmLicenseResponse struct for a top-level error.
    if (DRM_FAILED(drmLicenseResponse.m_dwResult)) {
        LOGGER(LERROR_, "Error in DRM_LICENSE_RESPONSE");
        return CDMi_S_FALSE;
    }

    // Finally, ensure that each license in the response was processed
    // successfully.
    const DRM_DWORD nLicenses = drmLicenseResponse.m_cAcks;
    for (uint32_t i=0; i < nLicenses; ++i)
    {
        LOGGER(LINFO_, "Checking license %d", i);
        if (DRM_FAILED(drmLicenseResponse.m_rgoAcks[i].m_dwResult)) {
            // Special handling for DRM_E_DST_STORE_FULL. If this error is
            // detected for any license, reset the DRM appcontext and return error.
            if (drmLicenseResponse.m_rgoAcks[i].m_dwResult == DRM_E_DST_STORE_FULL) {
                LOGGER(LINFO_, "Found DRM_E_DST_STORE_FULL error in license %d, reinitializing!", i);
                
                err = Drm_Reinitialize(m_poAppContext);
                if (DRM_FAILED(err))
                {
                    LOGGER(LERROR_, "Error: Drm_Reinitialize returned (error: 0x%08X)", static_cast<unsigned int>(err));
                    return CDMi_S_FALSE;
                }

            }
            else {
                LOGGER(LERROR_, "Error 0x%08lX found in license %d", (unsigned long)drmLicenseResponse.m_rgoAcks[i].m_dwResult, i);
            }
            return CDMi_S_FALSE;
        }
    }

    // === Extract various ID's from drmLicenseResponse
    //
    // There are 3 ID's in the processed license response we are interested in:
    // BID - License batch ID. A GUID that uniquely identifies a batch of
    //       licenses that were processed in one challenge/response transaction.
    //       The BID is a nonce unique to the transaction. If the transaction
    //       contains a single license, this is identical to the license nonce.
    //       The secure stop ID is set to the BID value.
    // KID - Key ID. A GUID that uniquely identifies the media content key. This
    //       is the primary index for items in the license store. There can be
    //       multiple licenses with the same KID.
    // LID - License ID. A GUID that uniquely identifies a license. This is the
    //       secondary index for items in the license store.
    // When there are multiple licenses in the server response as in the PRK
    // case, there are correspondingly multiple KID/LID entries in the processed
    // response. There is always only a single BID per server response.

    // BID
    mBatchId = drmIdToVectorId(&drmLicenseResponse.m_oBatchID);
    LOGGER(LINFO_, "BID: %s", vectorToHexString(mBatchId).c_str());
    // Microsoft says that a batch ID of all zeros indicates some sort of error
    // for in-memory licenses. Hopefully this error was already caught above.
    const std::vector<uint8_t> zeros(DRM_ID_SIZE, 0);

    if (std::equal(mBatchId.begin(), mBatchId.end(), zeros.begin())) {
        LOGGER(LERROR_, "No batch ID in processed response");
        return CDMi_S_FALSE;
    }
    // We take the batch ID as the secure stop ID
    secureStopId = &mBatchId[0];
    LOGGER(LINFO_, "SSID: %s", vectorToHexString(mBatchId).c_str());

    // KID and LID
    mLicenseIds.clear();
    mKeyIds.clear();
    LOGGER(LINFO_, "Found %d license%s in server response:", nLicenses, (nLicenses > 1) ? "s" : "");
    for (uint32_t i=0; i < nLicenses; ++i)
    {
        const DRM_LICENSE_ACK * const licAck = &drmLicenseResponse.m_rgoAcks[i];
        mLicenseIds.push_back(drmIdToVectorId(&licAck->m_oLID));
        mKeyIds.push_back    (drmIdToVectorId(&licAck->m_oKID));
        LOGGER(LINFO_, "KID[%d]:  %s", i, vectorToHexString(mKeyIds[i]).c_str());
    }

    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::InitDecryptContextByKid()
{
    // open scope for DRM_APP_CONTEXT mutex
    SafeCriticalSection systemLock(drmAppContextMutex_);
    
    DRM_RESULT err;
    // Seems like we no longer have to worry about invalid app context, make sure with this ASSERT.
    ASSERT(m_poAppContext != nullptr);

    // reinitialze DRM_APP_CONTEXT and set DRM header for current session for
    // simulataneous decryption support
    err = Drm_Reinitialize(m_poAppContext);
    if (DRM_FAILED(err))
    {
        LOGGER(LERROR_, "Error: Drm_Reinitialize (error: 0x%08X)", static_cast<unsigned int>(err));
        return CDMi_S_FALSE;
    }

    err = Drm_Content_SetProperty(
            m_poAppContext,
            DRM_CSP_AUTODETECT_HEADER,
            &mDrmHeader[0],
            mDrmHeader.size());
    if (DRM_FAILED(err)) {
        LOGGER(LERROR_, "Error: Drm_Content_SetProperty");
        return CDMi_S_FALSE;
    }

    if (m_decryptInited) {
        return CDMi_SUCCESS;
    }

    CDMi_RESULT result = CDMi_SUCCESS;

    if(m_oDecryptContext){
        Drm_Reader_Close(m_oDecryptContext);
        delete m_oDecryptContext;
        m_oDecryptContext = nullptr;
    }

    m_oDecryptContext = new DRM_DECRYPT_CONTEXT;
    //Create a decrypt context and bind it with the drm context.
    memset(m_oDecryptContext, 0, sizeof(DRM_DECRYPT_CONTEXT));

    LOGGER(LINFO_, "Drm_Reader_Bind");
    err = Drm_Reader_Bind(
            m_poAppContext,
            RIGHTS,
            sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
            &opencdm_output_levels_callback, 
            static_cast<const void*>(m_piCallback),
            m_oDecryptContext);
    if (DRM_FAILED(err))
    {
        LOGGER(LERROR_, "Error: Drm_Reader_Bind (error: 0x%08X)", static_cast<unsigned int>(err));
        return CDMi_S_FALSE;
    }

    // Commit all secure store transactions to the DRM store file. For the
    // Netflix use case, Drm_Reader_Commit only needs to be called after
    // Drm_Reader_Bind.
    LOGGER(LINFO_,"Drm_Reader_Commit");
    err = Drm_Reader_Commit(m_poAppContext, &opencdm_output_levels_callback, static_cast<const void*>(m_piCallback));
    if (DRM_FAILED(err))
    {
        LOGGER(LERROR_, "Error: Drm_Reader_Commit (error: 0x%08X)", static_cast<unsigned int>(err));
        return CDMi_S_FALSE;
    }

    if (result == CDMi_SUCCESS) {
        m_fCommit = TRUE;
        m_decryptInited = true;
    }

    return result;
}

CDMi_RESULT MediaKeySession::GetChallengeDataExt(uint8_t * challenge, uint32_t & challengeSize, uint32_t /* isLDL */)
{
    SafeCriticalSection systemLock(drmAppContextMutex_);
    
    // sanity check for drm header
    if (mDrmHeader.size() == 0) {
        LOGGER(LERROR_, "Error: No valid DRM header");
        return CDMi_S_FALSE;
    }

    DRM_RESULT err;

    // Seems like we no longer have to worry about invalid app context, make sure with this ASSERT.
    ASSERT(m_poAppContext != nullptr);

    // reinitialize DRM_APP_CONTEXT - this is limitation of PlayReady 2.x maybe also needed here.
    err = Drm_Reinitialize(m_poAppContext);
    if (DRM_FAILED(err))
    {
        LOGGER(LERROR_, "Error: Drm_Reinitialize (error: 0x%08X)", static_cast<unsigned int>(err));
        return CDMi_S_FALSE;
    }

    // Set this session's DMR header in the PR3 app context.
    err = Drm_Content_SetProperty(
            m_poAppContext,
            DRM_CSP_AUTODETECT_HEADER,
            &mDrmHeader[0],
            mDrmHeader.size());
    if (DRM_FAILED(err)) {
        LOGGER(LERROR_, "Error: Drm_Content_SetProperty");
        return CDMi_S_FALSE;
    }

    // Find the size of the challenge.
    LOGGER(LINFO_, "Drm_LicenseAcq_GenerateChallenge, querying challenge size");

    // PlayReady doesn't like valid pointer + size 0
    DRM_BYTE* passedChallenge = static_cast<DRM_BYTE*>(challenge);
    if (challengeSize == 0) {
        passedChallenge = nullptr;
    }
   
    err = Drm_LicenseAcq_GenerateChallenge(
            m_poAppContext,
            RIGHTS,
            sizeof(RIGHTS) / sizeof(DRM_CONST_STRING*),
            nullptr,
            nullptr, 0,
            nullptr, nullptr,
            nullptr, nullptr,
            passedChallenge, &challengeSize,
            nullptr);

    LOGGER(LINFO_, "ChallengeSize: %u\n", challengeSize);

    if ((err != DRM_E_BUFFERTOOSMALL) && (DRM_FAILED(err)))
    {
        LOGGER(LERROR_, "Error: Drm_LicenseAcq_GenerateChallenge_Netflix (error: 0x%08X)", static_cast<unsigned int>(err));
        return CDMi_S_FALSE;
    }

    if (err == DRM_E_BUFFERTOOSMALL) {
        LOGGER(LERROR_, "Error: Drm_LicenseAcq_GenerateChallenge_Netflix (error: 0x%08X)", static_cast<unsigned int>(err));
        return CDMi_OUT_OF_MEMORY ;
    }

    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::CancelChallengeDataExt()
{
    // NA
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::CleanDecryptContext()
{   
    SafeCriticalSection systemLock(drmAppContextMutex_);
    
    if (m_oDecryptContext != nullptr){
        Drm_Reader_Close(m_oDecryptContext);

        delete m_oDecryptContext;
        m_oDecryptContext = nullptr;
        m_fCommit = FALSE;
        m_decryptInited = false;
    }

    return CDMi_SUCCESS;
}

// Converts a PR3 DRM_ID to a std::vector. Assumes everything is sized correctly.
std::vector<unsigned char> MediaKeySession::drmIdToVectorId(const DRM_ID *drmId)
{
    assert(drmId);
    assert(sizeof(drmId->rgb) == DRM_ID_SIZE);
    if (!drmId){
        return std::vector<unsigned char>();
    }
    return std::vector<unsigned char>(drmId->rgb, drmId->rgb + DRM_ID_SIZE);
}

std::string MediaKeySession::vectorToHexString(const std::vector<uint8_t>& vec)
{
    static TCHAR HexArray[] = "0123456789ABCDEF";
    string result;

    for ( auto &i : vec ) {
        result += HexArray[i];
    }

    return (result);
}
}
