/*
 * Copyright 2017-2019 Metrological
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

#include <cstring>
#include <csignal>
#include "MediaSession.h"
#include <drmcompiler.h>

namespace CDMi {

class PlayReady : public IMediaKeys {
private:
    PlayReady (const PlayReady&) = delete;
    PlayReady& operator= (const PlayReady&) = delete;

public:
    PlayReady()
      : m_drmOemContext(nullptr) {

        NxClient_JoinSettings joinSettings;
        NEXUS_Error rc;
        NEXUS_ClientConfiguration platformConfig;
        NEXUS_MemoryAllocationSettings heapSettings;
        DRM_RESULT dr = DRM_S_FALSE;
#ifndef PLAYREADY_SAGE
        uint16_t cchStr = 0;
#endif
        BKNI_Memset(&sAllocResults, 0, sizeof(NxClient_AllocResults));

        NxClient_GetDefaultJoinSettings(&joinSettings);
        snprintf(joinSettings.name, NXCLIENT_MAX_NAME, "WPEProcess");
        joinSettings.ignoreStandbyRequest = true;
        rc = NxClient_Join(&joinSettings);
        if (rc) {
            printf("Playready: NxClient_Join() failed: %d\n", rc);
            goto ErrorExit;
        }

        /* Drm_Platform_Initialize */
        NEXUS_Memory_GetDefaultAllocationSettings(&heapSettings);
        NEXUS_Platform_GetClientConfiguration(&platformConfig);

        NxClient_AllocSettings nxAllocSettings;
        NxClient_GetDefaultAllocSettings(&nxAllocSettings);
        rc = NxClient_Alloc(&nxAllocSettings, &sAllocResults);
        if (rc) {
            printf("Playready: NxClient_Alloc() failed: %d\n", rc);
            goto ErrorExit;
        }

        if (platformConfig.heap[NXCLIENT_FULL_HEAP]) {
            NEXUS_HeapHandle heap = platformConfig.heap[NXCLIENT_FULL_HEAP];
            NEXUS_MemoryStatus heapStatus;
            NEXUS_Heap_GetStatus(heap, &heapStatus);
            printf("Playready: Nexus heap = %p\n", static_cast<void *>(heap));
            if (heapStatus.memoryType & NEXUS_MemoryType_eFull) {
                printf("Playready: Nexus using heap = %p at index = %d\n", static_cast<void *>(heap), NXCLIENT_FULL_HEAP);
                heapSettings.heap = heap;
            }
        }

        waitForDebugger();

#ifndef PLAYREADY_SAGE
        OEM_Settings oemSettings;
        BKNI_Memset(&oemSettings, 0, sizeof(OEM_Settings));

        oemSettings.heap               = heapSettings.heap;
        oemSettings.binFileName        = cstringToWChar(OEM_SETTINGS_binFileName);
        oemSettings.keyHistoryFileName = cstringToWChar(OEM_SETTINGS_keyHistoryFileName);
        oemSettings.defaultRWDirName   = cstringToWChar(OEM_SETTINGS_defaultRWDirName);

        printf("Playready: Initialization: bin = \"%s\", history = \"%s\", rwDir = \"%s\"\n",
                OEM_SETTINGS_binFileName,
                OEM_SETTINGS_keyHistoryFileName,
                OEM_SETTINGS_defaultRWDirName);

        dr = Drm_Platform_Initialize((void *)&oemSettings);
        printf("Playready: Initialization: dr = 0x%jX\n", static_cast<uintmax_t>(dr));
        ChkDR(dr);

        m_drmOemContext = oemSettings.f_pOEMContext;
        ChkMem(m_drmOemContext);
#endif
ErrorExit:
        if (DRM_FAILED(dr)) {
            printf("Playready Initialize failed\n");
        }
    }

    ~PlayReady(void) {
        if (m_drmOemContext) {
            Drm_Platform_Uninitialize(m_drmOemContext);
        }

        NxClient_Free(&sAllocResults);
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

        *f_ppiMediaKeySession = new CDMi::MediaKeySession(f_pbInitData, f_cbInitData, m_drmOemContext);

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

protected:
    DRM_WCHAR* cstringToWChar(const char *src) {
        DRM_WCHAR* dst = nullptr;

        do {
            if (src == nullptr) {
                break;
            }

            const auto length = strlen(src);

            if (length == 0) {
                break;
            }

            dst = reinterpret_cast<DRM_WCHAR *>(Oem_MemAlloc(sizeof(DRM_WCHAR) * (length + 1)));

            if (dst == nullptr) {
                break;
            }

            for (size_t i = 0; i < length; i++) {
                dst[i] = DRM_ONE_WCHAR(src[i], '\0');
            }

            dst[length] = DRM_ONE_WCHAR('\0', '\0');
        } while (0);

        return dst;
    }

    void waitForDebugger() {
        const bool waitForDebugger = getenv("PLAYREADY_DRM_SIGSTOP") ? true : false;
        if (waitForDebugger) {
           const pid_t pid = getpid();
           printf("Playready: waiting for debugger...\n");
           printf("Playready: Issue\n");
           printf("Playready: \t$ gdb -p %u\n", pid);
           printf("Playready: or\n");
           printf("Playready: \t$ kill -SIGCONT %u\n", pid);
           raise(SIGSTOP);
           printf("Playready: Process %u running...\n", pid);
        }
    }
private:
    DRM_VOID *m_drmOemContext;
    NxClient_AllocResults sAllocResults;
};

static SystemFactoryType<PlayReady> g_instance({"video/x-h264", "audio/mpeg"});

}  // namespace CDMi

CDMi::ISystemFactory* GetSystemFactory() {

    return (&CDMi::g_instance); 
}
