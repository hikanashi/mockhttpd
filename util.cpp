#include "util.h"


#include    <iostream>
#include    <iomanip>

namespace util
{


	static constexpr char LOWER_XDIGITS[] = "0123456789abcdef";

	std::string format_hex(const unsigned char *s, size_t len) 
	{
		std::string res;
		res.resize(len * 2);

		for (size_t i = 0; i < len; ++i)
		{
			unsigned char c = s[i];

			res[i * 2] = LOWER_XDIGITS[c >> 4];
			res[i * 2 + 1] = LOWER_XDIGITS[c & 0x0f];
		}
		return res;
	}

	std::string ascii_dump(const uint8_t *data, size_t len)
	{
		std::string res;

		for (size_t i = 0; i < len; ++i)
		{
			auto c = data[i];

			if (c >= 0x20 && c < 0x7f)
			{
				res += c;
			} 
			else 
			{
				res += '.';
			}
		}

		return res;
	}


	void dumpbinary(const uint8_t* data, size_t datalen)
	{
		return;

		size_t count = 0;
		const uint8_t* dump = data;
		while( count < datalen )
		{

			if( count >= 16 * 10 )
			{

				break;
			}

			// display line
			if( count % 16 == 0 )
			{
				std::cout   << std::setw( 8 )     
							<< std::setfill( '0' ) 
							<< std::hex  
							<< std::uppercase
							<< count
							<< " ";
			}

			// display data
			printf("%02X ", (int)dump[count]);
			//std::cout   << std::setw( 2 )  
			//			<< std::setfill( '0' )
			//			<< std::hex         
			//			<< std::uppercase  
			//			<< ( int )dump[count]
			//			<< " ";

			if( count % 16 == 15 )
			{
        		std::cout << std::endl;
			}

			++count;

		}

		if( count % 16 != 0 )
		{
    		std::cout << std::endl;
		}

	}

	std::string& ltrim(std::string& str, const std::string& chars)
	{
		str.erase(0, str.find_first_not_of(chars));
		return str;
	}

	std::string& rtrim(std::string& str, const std::string& chars)
	{
		str.erase(str.find_last_not_of(chars) + 1);
		return str;
	}

	std::string& trim(std::string& str, const std::string& chars)
	{
		return ltrim(rtrim(str, chars), chars);
	}

	void split_string(const std::string& src, const std::string& separator, std::vector<std::string>& dst)
	{
		size_t separator_length = separator.size();
		if (separator_length == 0)
		{
			dst.push_back(src);
			return;
		}


		auto offset = std::string::size_type(0);
		while (offset < src.size())
		{
			auto pos = src.find(separator, offset);
			if (pos == std::string::npos)
			{
				dst.push_back(src.substr(offset));
				break;
			}
			dst.push_back(src.substr(offset, pos - offset));
			offset = pos + separator_length;
		}
	}

}
