#ifndef UTIL_H_
#define UTIL_H_

#include "Common.h"
#include <string>
#include <vector>

namespace util
{

	std::string& ltrim(std::string& str, const std::string& chars = "\t\n\v\f\r ");
	std::string& rtrim(std::string& str, const std::string& chars = "\t\n\v\f\r ");
	std::string& trim(std::string& str, const std::string& chars = "\t\n\v\f\r ");

	void split_string(const std::string& src, const std::string& separator, std::vector<std::string>& dst);

	std::string format_hex(const unsigned char *s, size_t len);

	template <size_t N> std::string format_hex(const unsigned char (&s)[N])
	{
		return format_hex(s, N);
	}

	template <size_t N> std::string format_hex(const std::array<uint8_t, N> &s)
	{
		return format_hex(s.data(), s.size());
	}

	// Returns ASCII dump of |data| of length |len|.  Only ASCII printable
	// characters are preserved.  Other characters are replaced with ".".
	std::string ascii_dump(const uint8_t *data, size_t len);

	void dumpbinary(const uint8_t* data, size_t datalen);

}

#endif /* UTIL_H_ */
