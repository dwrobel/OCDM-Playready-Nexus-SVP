#include "MediaSession.h"

namespace CDMi {
uint32_t MediaKeySession::GetSessionIdExt() const
{    
    // TODO
    return 0;
}

CDMi_RESULT MediaKeySession::SetDrmHeader(const uint8_t drmHeader[], uint32_t drmHeaderLength)
{
    // TODO
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::StoreLicenseData(const uint8_t licenseData[], uint32_t licenseDataSize, uint8_t * secureStopId)
{
    // TODO
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::InitDecryptContextByKid()
{
    // TODO
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::GetChallengeDataExt(uint8_t * challenge, uint32_t & challengeSize, uint32_t isLDL)
{
    // TODO
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::CancelChallengeDataExt()
{
    // TODO
    return CDMi_SUCCESS;
}

CDMi_RESULT MediaKeySession::CleanDecryptContext()
{
    // TODO
    return CDMi_SUCCESS;
}
}
