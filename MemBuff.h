#ifndef MEMBUFF_H_
#define MEMBUFF_H_

#include "Common.h"
#include <vector>
#include <cstddef>


class MemBuff
{
public:
	MemBuff() {};
	virtual ~MemBuff() {};

	uint8_t* pos()
	{
		return buffer_.data();
	}

	size_t size()
	{
		return buffer_.size();
	}

	size_t capacity()
	{
		return buffer_.capacity();
	}

	void reserve(size_t datalen)
	{
		buffer_.reserve(datalen);
	}

	bool  IsFull()
	{
		if( buffer_.capacity() == buffer_.size() )
		{
			return true;
		}
		else
		{
			return false;
		}
	}

	void add(const uint8_t *data, size_t datalen)
	{
		if( datalen == 0)
		{
			return;
		}

		if(buffer_.capacity() < buffer_.size()+ datalen )
		{
			buffer_.reserve(buffer_.size()+ datalen);
		}

		std::vector<uint8_t> buf(&data[0],&data[datalen]);
		std::copy(buf.begin(),buf.end(),std::back_inserter(buffer_));

	}

	void drain(size_t len)
	{
		if( len == 0)
		{
			return;
		}

		std::vector<uint8_t>::iterator endit = buffer_.begin();
		endit += len;
		buffer_.erase(buffer_.begin(), endit);
	}

private:
	std::vector<uint8_t> buffer_;

};

#endif /* MEMBUFF_H_ */
