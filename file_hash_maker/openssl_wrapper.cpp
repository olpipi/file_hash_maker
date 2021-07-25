
#include <openssl/md5.h>
#include "openssl_wrapper.h"


std::unique_ptr<unsigned char[]> MD5Hash::CalsHash(std::unique_ptr<unsigned char[]> dataToHash, uint32_t size)
{
    MD5_CTX md5Ctx {};
    auto md5digest = std::make_unique<unsigned char[]>(MD5_DIGEST_LENGTH);

    if (1 != MD5_Init(&md5Ctx))
        throw MD5Exception("failed to init MD5 hash");

    if (1 != MD5_Update(&md5Ctx, static_cast<const void*>(dataToHash.get()), size))
        throw MD5Exception("failed to put data for MD5");

    if (1 != MD5_Final(md5digest.get(), &md5Ctx))
        throw MD5Exception("failed to get result from MD5");

    return md5digest;
}