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

#include "cdmi.h"
#include "MediaSession.h"

#include <drmconstants.h>

namespace CDMi {

class PlayReady : public IMediaKeys {
private:
    PlayReady (const PlayReady&) = delete;
    PlayReady& operator= (const PlayReady&) = delete;

public:
    PlayReady() 
        : m_drmOemContext(nullptr)
        , m_nxAllocResults() {
        NxClient_JoinSettings joinSettings;
        NxClient_AllocSettings nxAllocSettings;
        NEXUS_Error rc;
        NEXUS_ClientConfiguration platformConfig;
        OEM_Settings         oemSettings;
        NEXUS_MemoryAllocationSettings heapSettings;
        DRM_RESULT dr = DRM_SUCCESS;

        NxClient_GetDefaultJoinSettings(&joinSettings);
        snprintf(joinSettings.name, NXCLIENT_MAX_NAME, "playready3x");
        joinSettings.ignoreStandbyRequest = true;
        rc = NxClient_Join(&joinSettings);
        if (rc) {
            LOGGER(LERROR_, "Couldnt join nxserver [rc=0x%08X]", rc);
            goto ErrorExit;
        }

        NxClient_GetDefaultAllocSettings(&nxAllocSettings);
        rc = NxClient_Alloc(&nxAllocSettings, &m_nxAllocResults);
        
        if (rc) {
            LOGGER(LERROR_, "NxClient_Alloc failed nxserver [rc=0x%08X]", rc);
            goto ErrorExit;
        }

        /* Drm_Platform_Initialize */
        NEXUS_Memory_GetDefaultAllocationSettings(&heapSettings);
        NEXUS_Platform_GetClientConfiguration(&platformConfig);
        if (platformConfig.heap[NXCLIENT_FULL_HEAP])
        {
            NEXUS_HeapHandle heap = platformConfig.heap[NXCLIENT_FULL_HEAP];
            NEXUS_MemoryStatus heapStatus;
            NEXUS_Heap_GetStatus(heap, &heapStatus);
            if (heapStatus.memoryType & NEXUS_MemoryType_eFull)
            {
                heapSettings.heap = heap;
            }
        }

        BKNI_Memset(&oemSettings, 0, sizeof(OEM_Settings));
        oemSettings.heap = heapSettings.heap;

        oemSettings.binFileName = nullptr;
        oemSettings.keyHistoryFileName = nullptr;
        oemSettings.defaultRWDirName = nullptr;

        char * oemSettingsEnvironment;

        /* copy the defaultRWDirName if provided */
        oemSettingsEnvironment = getenv( "PR_BIN_FILE_NAME" );
        if( (oemSettingsEnvironment != NULL))
        {
            DRM_DWORD  cchStr = 0;
            oemSettings.binFileName = (DRM_WCHAR *)Oem_MemAlloc(sizeof(DRM_WCHAR) * DRM_MAX_PATH);
            if( !convertCStringToWString((char *)oemSettingsEnvironment, oemSettings.binFileName, &cchStr))
            {
                SAFE_OEM_FREE(oemSettings.binFileName);
            }
            LOGGER(LINFO_, "Found PR_BIN_FILE_NAME binFileName=%s", oemSettingsEnvironment);
        }

        /* copy the defaultRWDirName if provided */
        oemSettingsEnvironment = getenv( "PR_KEY_HISTORY_FILE_NAME" );
        if( (oemSettingsEnvironment != NULL))
        {
            DRM_DWORD  cchStr = 0;
            oemSettings.keyHistoryFileName = (DRM_WCHAR *)Oem_MemAlloc(sizeof(DRM_WCHAR) * DRM_MAX_PATH);
            if( !convertCStringToWString((char *)oemSettingsEnvironment, oemSettings.keyHistoryFileName, &cchStr))
            {
                SAFE_OEM_FREE(oemSettings.keyHistoryFileName);
            }
            LOGGER(LINFO_, "Found PR_KEY_HISTORY_FILE_NAME keyHistoryFileName=%s", oemSettingsEnvironment);       
        }

        /* copy the defaultRWDirName if provided */
        oemSettingsEnvironment = getenv( "PR_DEFAULT_RW_DIR_NAME" );
        if( (oemSettingsEnvironment != NULL))
        {
            DRM_DWORD  cchStr = 0;
            oemSettings.defaultRWDirName = (DRM_WCHAR *)Oem_MemAlloc(sizeof(DRM_WCHAR) * DRM_MAX_PATH);
            if( !convertCStringToWString((char *)oemSettingsEnvironment, oemSettings.defaultRWDirName, &cchStr))
            {
                SAFE_OEM_FREE(oemSettings.defaultRWDirName);
            }
            LOGGER(LINFO_, "Found PR_DEFAULT_RW_DIR_NAME defaultRWDirName=%s", oemSettingsEnvironment);
        }

        ChkDR(Drm_Platform_Initialize((void *)&oemSettings));

        m_drmOemContext = oemSettings.f_pOEMContext;
        ChkMem(m_drmOemContext);

ErrorExit:
        if (DRM_FAILED(dr))
        {
            LOGGER(LERROR_, "Playready Initialize failed (error: 0x%08X)", static_cast<unsigned int>(dr));
        }
    }

    ~PlayReady(void) {
        NxClient_Free(&m_nxAllocResults);
        NxClient_Uninit();

        Drm_Platform_Uninitialize(m_drmOemContext);
    }

    CDMi_RESULT CreateMediaKeySession(
        const std::string& /* keySystem */,
        int32_t licenseType,
        const char *f_pwszInitDataType,
        const uint8_t *f_pbInitData,
        uint32_t f_cbInitData, 
        const uint8_t *f_pbCDMData,
        uint32_t f_cbCDMData, 
        IMediaKeySession **f_ppiMediaKeySession) {

        *f_ppiMediaKeySession = new CDMi::MediaKeySession(f_pbInitData, f_cbInitData, f_pbCDMData, f_cbCDMData, m_drmOemContext);

        return CDMi_SUCCESS; 
    }

    CDMi_RESULT SetServerCertificate(
        const uint8_t *f_pbServerCertificate,
        uint32_t f_cbServerCertificate) {

        return CDMi_S_FALSE;
    }

    CDMi_RESULT DestroyMediaKeySession(IMediaKeySession *f_piMediaKeySession) {

        delete f_piMediaKeySession;

        return CDMi_SUCCESS;
    }

private:
    bool convertCStringToWString( char * pCStr, DRM_WCHAR * pWStr, DRM_DWORD * cchStr)
    {
        DRM_RESULT         dr = DRM_SUCCESS;
        bool               result = false;
        DRM_SUBSTRING      tmpSubStr;
        DRM_CHAR           tmpCStr[ DRM_MAX_PATH ];
        DRM_WCHAR          tmpWChar[ DRM_MAX_PATH ];
        DRM_STRING         tmpWStr;

        if(( pCStr != NULL) && (pWStr != NULL))
        {
            /* Convert the given char * to DRM_CHAR * */
            BKNI_Memset(tmpCStr, 0, (DRM_MAX_PATH * sizeof(DRM_CHAR)));
            ChkDR( DRM_STR_StringCchCopyA(
                    tmpCStr,
                    sizeof(tmpCStr),
                    pCStr) );

            /* Make sure tmpWChar is NULL terminated */
            BKNI_Memset(tmpWChar, 0, (DRM_MAX_PATH * sizeof(DRM_WCHAR)));

            tmpSubStr.m_ich = 0;
            tmpSubStr.m_cch = strlen( (char*)tmpCStr );

            /* Convert the DRM_CHAR * to DRM_STRING. */
            tmpWStr.pwszString = tmpWChar;
            tmpWStr.cchString  = DRM_MAX_PATH;
            DRM_UTL_PromoteASCIItoUNICODE( tmpCStr,
                                        &tmpSubStr,
                                        &tmpWStr);

            BKNI_Memcpy(pWStr, tmpWStr.pwszString, (tmpWStr.cchString+1) * sizeof (DRM_WCHAR));
            *cchStr = tmpWStr.cchString;
            pWStr[tmpWStr.cchString] = g_wchNull;
            result = true;
        }

    ErrorExit:
        return result;
    }

    DRM_VOID *m_drmOemContext;
    NxClient_AllocResults m_nxAllocResults;
};

static SystemFactoryType<PlayReady> g_instance({"video/x-h264", "audio/mpeg"});

}  // namespace CDMi

CDMi::ISystemFactory* GetSystemFactory() {

    return (&CDMi::g_instance); 
}
