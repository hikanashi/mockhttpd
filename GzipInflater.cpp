#include "GzipInflater.h"

GzipInflater::GzipInflater(size_t max, size_t extendsize)
	: maxsize_(max)
	, zst_()
	, finished_(0)
	, buff_(max)
	, usedsize_(0)
	, extendsize_(extendsize)
{
	auto zst = std::unique_ptr<z_stream>(new z_stream);
	zst->next_in = Z_NULL;
	zst->avail_in = 0;
	zst->zalloc = Z_NULL;
	zst->zfree = Z_NULL;
	zst->opaque = Z_NULL;

	int rv = ::inflateInit2(zst.get(), 47);
	if (rv != Z_OK)
	{
		return;
	}

	buff_.resize(max);
	zst_.reset(zst.get());
	zst.release();
}

GzipInflater::~GzipInflater()
{
	if(zst_ != nullptr)
	{
		::inflateEnd(zst_.get());
	}
}


size_t	GzipInflater::size()
{
	return usedsize_;
}
uint8_t*	GzipInflater::data()
{
	return buff_.data();
}

int GzipInflater::inflate(const uint8_t *in,
			size_t *inlen_ptr)
{
	if(zst_ == nullptr)
	{
		return -1;
	}

	if (finished_ != 0 )
	{
		return -1;
	}

	int rv = 0;

	zst_->avail_in = (unsigned int) *inlen_ptr;
	zst_->next_in = (unsigned char *) in;
	zst_->avail_out = buff_.capacity() - usedsize_;
	zst_->next_out = buff_.data() + usedsize_;

	rv = ::inflate(zst_.get(), Z_NO_FLUSH);

	*inlen_ptr -= zst_->avail_in;
	usedsize_ = buff_.capacity() - zst_->avail_out;


	if( (buff_.capacity() - usedsize_)  < extendsize_)
	{
		buff_.resize(buff_.size() + extendsize_ );
	}


	switch (rv)
	{
	case Z_STREAM_END:
		finished_ = 1;
		/* FALL THROUGH */
	case Z_OK:
	case Z_BUF_ERROR:
		rv = 0;
		break;
	case Z_DATA_ERROR:
	case Z_STREAM_ERROR:
	case Z_NEED_DICT:
	case Z_MEM_ERROR:
		warnx("##########inflate error %d",rv);
		rv = -1;
		break;
	default:
		rv = 0;
		break;
	}

	return rv;
}

