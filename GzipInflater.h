#ifndef GZIPINFLATER_H_
#define GZIPINFLATER_H_

#include "Common.h"
#include <zlib.h>
#include <vector>

class GzipInflater
{
public:
	GzipInflater(size_t max, size_t appendsize);
	virtual ~GzipInflater();

	int inflate(const uint8_t *in,
				size_t *inlen_ptr);

	bool IsFinished() { return ( finished_ != 0 ); }
	size_t		size();
	uint8_t*	data();

private:
	size_t maxsize_;
	std::unique_ptr<z_stream> zst_;
	int8_t finished_;
	std::vector<uint8_t>	buff_;
	unsigned int usedsize_;
	unsigned int extendsize_;

};

#endif /* GZIPINFLATER_H_ */
