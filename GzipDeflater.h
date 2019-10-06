#ifndef GZIPDEFLATER_H_
#define GZIPDEFLATER_H_

#include "Common.h"
#include <zlib.h>
#include <vector>

class GzipDeflater
{
public:
	GzipDeflater(size_t max, size_t appendsize);
	virtual ~GzipDeflater();

	int deflate(const uint8_t *in,
				size_t *inlen_ptr,
				bool finish);

	bool IsFinished() { return ( finished_ != 0 ); }
	size_t		size();
	uint8_t*	data();

private:
	size_t maxsize_;
	std::unique_ptr<z_stream> zst_;
	int8_t finished_;
	std::vector<uint8_t>	buff_;
	size_t usedsize_;
	size_t extendsize_;
};

#endif /* GZIPDEFLATER_H_ */
