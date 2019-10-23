#ifndef OPENSSLTYPES_H_
#define OPENSSLTYPES_H_

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/ocsp.h>
#include <memory>

namespace openssl
{

	namespace internal
	{
		template <typename T>
		struct DeleterImpl {};

		template <typename T>
		struct Deleter
		{
			void operator()(T *ptr)
			{
				DeleterImpl<T>::Free(ptr);
			}
		};
	};

#define OPENSSL_MAKE_DELETER(type, deleter)		\
	namespace internal							\
	{											\
		template <>								\
		struct DeleterImpl<type> {				\
			static void Free(type *ptr) {		\
				deleter(ptr);					\
			}									\
		};										\
	};

	// This makes a unique_ptr to STACK_OF(type) that owns all elements on the
	// stack, i.e. it uses sk_pop_free() to clean up.
#define OPENSSL_MAKE_STACK_DELETER(type, deleter)		\
	namespace internal									\
	{													\
		template <>										\
		struct DeleterImpl<STACK_OF(type)> {			\
			static void Free(STACK_OF(type) *ptr) {		\
				sk_##type##_pop_free(ptr, deleter);		\
			}											\
		};												\
	};

// Holds ownership of heap-allocated OPENSSL structures. Sample usage:
//   openssl::UniquePtr<BIO> rsa(RSA_new());
//   openssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
	template <typename T>
	using UniquePtr = std::unique_ptr<T, internal::Deleter<T>>;

	OPENSSL_MAKE_DELETER(BIO, BIO_free)
	OPENSSL_MAKE_DELETER(EVP_PKEY, EVP_PKEY_free)
	OPENSSL_MAKE_DELETER(DH, DH_free)
	OPENSSL_MAKE_DELETER(X509, X509_free)
	OPENSSL_MAKE_DELETER(SSL, SSL_free)
	OPENSSL_MAKE_DELETER(SSL_CTX, SSL_CTX_free)
	OPENSSL_MAKE_DELETER(SSL_SESSION, SSL_SESSION_free)
	OPENSSL_MAKE_DELETER(OCSP_REQUEST, OCSP_REQUEST_free)
	OPENSSL_MAKE_DELETER(OCSP_CERTID, OCSP_CERTID_free)
	OPENSSL_MAKE_DELETER(OCSP_BASICRESP, OCSP_BASICRESP_free)
	OPENSSL_MAKE_DELETER(OCSP_RESPONSE, OCSP_RESPONSE_free)
	OPENSSL_MAKE_DELETER(X509_STORE_CTX, X509_STORE_CTX_free)
	OPENSSL_MAKE_DELETER(STACK_OF(OPENSSL_STRING), X509_email_free)
};



#endif /* OPENSSLTYPES_H_ */
