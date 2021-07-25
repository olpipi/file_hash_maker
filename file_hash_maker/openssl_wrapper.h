
#include <iostream>
#include <openssl/md5.h>
#include <vector>


class MD5Exception : public std::exception
{
public:
	MD5Exception(char const* const _Message) noexcept
		:std::exception(_Message)
	{}
};


class MD5Hash
{
public:
	static std::unique_ptr<unsigned char[]> CalsHash(std::unique_ptr<unsigned char[]>, uint32_t);
	//return size is always == MD5_DIGEST_LENGTH
};