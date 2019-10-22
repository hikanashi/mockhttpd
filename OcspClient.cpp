#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN 
#endif

#include "OcspClient.h"
#include <evhttp.h>
#include <openssl/ocsp.h>
#include <curl/curl.h>
#include "http-parser/http_parser.h"

#define base64_encoded_length(len)  (((len + 2) / 3) * 4)
#define OCSP_ESCAPE_URI            0
#define OCSP_ESCAPE_ARGS           1
#define OCSP_ESCAPE_URI_COMPONENT  2
#define OCSP_ESCAPE_HTML           3
#define OCSP_ESCAPE_REFRESH        4
#define OCSP_ESCAPE_MEMCACHED      5
#define OCSP_ESCAPE_MAIL_AUTH      6


static u_char   basis64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void request_finished(struct evhttp_request *req, void *arg)
{
	const int errcode = EVUTIL_SOCKET_ERROR();
	OcspClient* ocspcli = static_cast<OcspClient*>(arg);
	ocspcli->finish(req, errcode);
	ocspcli->clear_request();

}

static int
ssl_certificate_status_callback(SSL* ssl, void* data)
{
	OcspClient* ocspcli = static_cast<OcspClient *>(data);

	int rc = ocspcli->certificate_status(ssl);
	return rc;
}



static int ssl_verify_callback(int ok, X509_STORE_CTX *x509_store)
{

#if (1)
	char*				subject;
	char*				issuer;
	int					err;
	int					depth;
	X509*				cert;
	X509_NAME*			xsname;
	X509_NAME*			xiname;

	cert = X509_STORE_CTX_get_current_cert(x509_store);
	err = X509_STORE_CTX_get_error(x509_store);
	depth = X509_STORE_CTX_get_error_depth(x509_store);

	xsname = X509_get_subject_name(cert);
	subject = xsname ? X509_NAME_oneline(xsname, NULL, 0) : "(none)";

	xiname = X509_get_issuer_name(cert);
	issuer = xiname ? X509_NAME_oneline(xiname, NULL, 0) : "(none)";

	warnx("verify:%d, error:%d, depth:%d, "
		"subject:\"%s\", issuer:\"%s\"",
		ok, err, depth, subject, issuer);
	if (ok != 1)
	{
		warnx("(%s)", X509_verify_cert_error_string(err));
	}

	if (xsname)
	{
		OPENSSL_free(subject);
	}

	if (xiname)
	{
		OPENSSL_free(issuer);
	}
#endif

	return 1;
}


OcspClient::OcspClient(
		EventHandler&	ev,
		SSL_CTX*		ssl_ctx,
		X509*			cert)
	: event_(ev)
	, request_(NULL)
	, conn_(NULL)
	, bev_(NULL)
	, verify_(false)
	, ssl_ctx_(ssl_ctx)
	, cert_(cert)
	, host_()
	, port_()
	, path_()
	, timeout_sec(2)
	, retry_max(1)
{
}

OcspClient::~OcspClient()
{
	clear_request();

	if (cert_ != NULL)
	{
		X509_free(cert_);
		cert_ = NULL;
	}
}

void OcspClient::clear_request()
{
	if (conn_ != NULL)
	{
		evhttp_connection_free(conn_);
		conn_ = NULL;
	}

	// free include evhttp_connection_free
	if (bev_ != NULL)
	{
		bev_ = NULL;
	}

	// free include evhttp_connection_free
	if (request_ != NULL)
	{
		request_ = NULL;
	}
}

int32_t OcspClient::init(
	std::string& response_file,
	bool stapling_verify)
{
	verify_ = stapling_verify;

	int32_t rc = setup_stapling(response_file);

	if (rc == 0)
	{
		SSL_CTX_set_tlsext_status_arg(ssl_ctx_, this);
		SSL_CTX_set_tlsext_status_cb(ssl_ctx_, ssl_certificate_status_callback);
	}

	return rc;
}

int32_t OcspClient::setup_stapling(
	std::string& res_file)
{
	int rc = 0;

	if (res_file.length() > 0)
	{
		/* use OCSP response from the file */
		rc = stapling_file(res_file);
		if (rc < 0)
		{
			return -1;
		}

		if (rc == 0)
		{
			warnx("Loading ocsp response from '%s' size=%d",
				res_file.c_str(), ocsp_response_.size());

			return 0;
		}
	}

	response_file_ = res_file;

	rc = stapling_certificate();
	if (rc < 0)
	{
		return rc;
	}

	stapling_update(cert_);


	return 0;
}

int32_t OcspClient::stapling_file(
	std::string& res_file)
{
#if 0
	struct stat buf;
	int result = stat(res_file.c_str(), &buf);
	if (result != 0)
	{
		warnx("(\"%s\") can't access",
			res_file.c_str());
		return 1;
	}

	ocsp_response_.resize(buf.st_size);
	
	BIO* bio = BIO_new_file(res_file.c_str(), "rb");
	if (bio == NULL)
	{
		warnx("ocsp response BIO_new_file(\"%s\") not exist",
			res_file.c_str());
		return 1;
	}

	int readsize= BIO_read(bio, ocsp_response_.data(), ocsp_response_.size());
	BIO_free(bio);

	if (readsize != ocsp_response_.size())
	{
		return -1;
	}

	return 0;

#else
	BIO* bio = BIO_new_file(res_file.c_str(), "rb");
	if (bio == NULL)
	{
		warnx("ocsp response BIO_new_file(\"%s\") not exist",
			res_file.c_str());
		return 1;
	}

	OCSP_RESPONSE* response = d2i_OCSP_RESPONSE_bio(bio, NULL);
	if (response == NULL)
	{
		warnx("d2i_OCSP_RESPONSE_bio(\"%s\") failed",
			res_file.c_str());
		BIO_free(bio);
		return -1;
	}

	int len = i2d_OCSP_RESPONSE(response, NULL);
	if (len <= 0)
	{
		warnx("i2d_OCSP_RESPONSE(\"%s\") failed",
			res_file.c_str());
		goto failed;
	}

	ocsp_response_.resize(len);
	unsigned char* buf = ocsp_response_.data();

	len = i2d_OCSP_RESPONSE(response, &buf);
	if (len <= 0)
	{
		warnx("i2d_OCSP_RESPONSE(\"%s\") failed",
			res_file.c_str());
		ocsp_response_.clear();
		goto failed;
	}

	OCSP_RESPONSE_free(response);
	BIO_free(bio);

	return 0;

failed:
	OCSP_RESPONSE_free(response);
	BIO_free(bio);

	return -1;
#endif
}

int32_t OcspClient::stapling_certificate()
{
	int rc = 0;


	STACK_OF(X509)  *chain = NULL;
	X509*			cert = cert_;


	rc = SSL_CTX_get0_chain_certs(ssl_ctx_, &chain);
	if (rc != 1)
	{
		return -1;
	}

	int n = sk_X509_num(chain);
	n++;

	for(int i=0; i < n; i++)
	{
		if (i != 0)
		{
			cert = sk_X509_shift(chain);
		}

		rc = stapling_responder(cert);

		if (rc <= 0)
		{
			return rc;
		}
	}

	return 0;
}

int32_t OcspClient::stapling_issuer(
	X509*	cert)
{
	X509            *issuer = NULL;
	X509_STORE      *store = NULL;
	X509_STORE_CTX  *store_ctx = NULL;
	STACK_OF(X509)  *chain = NULL;

#ifdef SSL_CTRL_SELECT_CURRENT_CERT
	/* OpenSSL 1.0.2+ */
	SSL_CTX_select_current_cert(ssl_ctx_, cert);
#endif

#ifdef SSL_CTRL_GET_EXTRA_CHAIN_CERTS
	/* OpenSSL 1.0.1+ */
	SSL_CTX_get_extra_chain_certs(ssl_ctx_, &chain);
#else
	chain = ssl_ctx_->extra_certs;
#endif

	int n = sk_X509_num(chain);

	warnx("SSL get issuer: %d extra certs %s", n, commonName(cert).c_str());

	for (int i = 0; i < n; i++)
	{
		issuer = sk_X509_value(chain, i);
		if (X509_check_issued(issuer, cert) == X509_V_OK)
		{
#if OPENSSL_VERSION_NUMBER >= 0x10100001L
			X509_up_ref(issuer);
#else
			CRYPTO_add(&issuer->references, 1, CRYPTO_LOCK_X509);
#endif

			warnx("SSL get issuer: found %p in extra certs %s", issuer, commonName(issuer).c_str());

			issuer_ = issuer;

			return 0;
		}
	}

	store = SSL_CTX_get_cert_store(ssl_ctx_);
	if (store == NULL) 
	{
		warnx("SSL_CTX_get_cert_store() failed");
		return -1;
	}

	store_ctx = X509_STORE_CTX_new();
	if (store_ctx == NULL)
	{
		warnx("X509_STORE_CTX_new() failed");
		return -1;
	}

	if (X509_STORE_CTX_init(store_ctx, store, NULL, NULL) == 0)
	{
		warnx("X509_STORE_CTX_init() failed");
		X509_STORE_CTX_free(store_ctx);
		return -1;
	}

	int rc = X509_STORE_CTX_get1_issuer(&issuer, store_ctx, cert);

	if (rc == -1) 
	{
		warnx("X509_STORE_CTX_get1_issuer() failed %s", commonName(cert).c_str());
		X509_STORE_CTX_free(store_ctx);
		return -1;
	}

	if (rc == 0) {
		errx(1,"\"ssl_stapling\" ignored, "
			"issuer certificate not found for certificate %s", commonName(cert).c_str());
		X509_STORE_CTX_free(store_ctx);
		return -1;
	}

	X509_STORE_CTX_free(store_ctx);

	warnx("SSL get issuer: found %p in cert store(%s)", issuer, commonName(cert).c_str());

	issuer_ = issuer;

	return 0;
}


int32_t OcspClient::stapling_responder(
		X509*	cert)
{
	char                      *s = NULL;
	STACK_OF(OPENSSL_STRING)  *aia = NULL;

	if (reponder_.length() == 0)
	{

		/* extract OCSP responder URL from certificate */

		aia = X509_get1_ocsp(cert);
		if (aia == NULL) 
		{
			warnx("\"ssl_stapling\" ignored, "
				"no OCSP responder URL in the certificate %s", commonName(cert).c_str());
			return 1;
		}

#if OPENSSL_VERSION_NUMBER >= 0x10000000L
		s = sk_OPENSSL_STRING_value(aia, 0);
#else
		s = sk_value(aia, 0);
#endif
		if (s == NULL)
		{
			warnx("\"ssl_stapling\" ignored, "
				"no OCSP responder URL in the certificate %s", commonName(cert).c_str());
			X509_email_free(aia);
			return 1;
		}

		reponder_.assign(s);
		X509_email_free(aia);
	}

	struct http_parser_url u = { 0 };
	const char*	uri = reponder_.c_str();
	int rv = http_parser_parse_url(uri, reponder_.length(), 0, &u);
	if (rv != 0)
	{
		errx(1, "Could not parse URI %s", uri);
		return -1;
	}

	if (u.field_set & (1 << UF_SCHEMA))
	{
		if (strncasecmp(uri, "http", u.field_data[UF_SCHEMA].len) != 0)
		{
			warnx("\"ssl_stapling\" ignored, "
				"invalid URL prefix in OCSP responder \"%V\" "
				"in the certificate %s",
				uri, commonName(cert).c_str());
			return 1;
		}
	}

	if (u.field_set & (1 << UF_HOST))
	{
		host_.assign(
			&uri[u.field_data[UF_HOST].off],
			u.field_data[UF_HOST].len);
	}

	if (u.field_set & (1 << UF_PORT))
	{
		std::string portstr;
		portstr.assign(
			&uri[u.field_data[UF_PORT].off],
			u.field_data[UF_PORT].len);
		port_ = std::atoi(portstr.c_str());
	}
	else
	{
		port_ = 80;
	}

	if (u.field_set & (1 << UF_PATH))
	{
		path_.assign(
			&uri[u.field_data[UF_PATH].off],
			u.field_data[UF_PATH].len);
	}
	else
	{
		path_ = "/";
	}

	if (u.field_set & (1 << UF_QUERY))
	{
		path_.append(
			&uri[u.field_data[UF_QUERY].off - 1],
			u.field_data[UF_QUERY].len + 1);
	}

	if (u.field_set & (1 << UF_FRAGMENT))
	{
		path_.append(
			&uri[u.field_data[UF_FRAGMENT].off - 1],
			u.field_data[UF_FRAGMENT].len + 1);
	}

	return 0;
}

int OcspClient::certificate_status(
	SSL *ssl)
{
	//	warnx("SSL certificate status callback");

	int rc = SSL_TLSEXT_ERR_NOACK;

	X509* cert = SSL_get_certificate(ssl);

	if (cert == NULL)
	{
		return rc;
	}

	if (ocsp_response_.size() > 0)
	{
		/* we have to copy ocsp response as OpenSSL will free it by itself */
		size_t buflen = ocsp_response_.size();
		unsigned char* ocsp_resp = (unsigned char*)OPENSSL_malloc(buflen);
		if (ocsp_resp == NULL)
		{
			errx(1, "OPENSSL_malloc() failed. so can't send ocsp response");
			return SSL_TLSEXT_ERR_NOACK;
		}

		memcpy(ocsp_resp, ocsp_response_.data(), buflen);

		SSL_set_tlsext_status_ocsp_resp(ssl, ocsp_resp, buflen);


		const unsigned char* res = ocsp_resp;
		OCSP_RESPONSE* ocsp = d2i_OCSP_RESPONSE(NULL, &res, buflen);
		if (ocsp == NULL)
		{
			warnx("d2i_OCSP_RESPONSE() failed");
		}
		else
		{
			int resp_status = OCSP_response_status(ocsp);

			if (resp_status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
			{
				warnx("OCSP response not successful (%d: %s)",
					resp_status, OCSP_response_status_str(resp_status));
			}
		}


		rc = SSL_TLSEXT_ERR_OK;
	}

	warnx("certificate_status %s", commonName(cert).c_str());

	stapling_update(cert);

	return rc;

}



void OcspClient::stapling_update(
						X509*	cert)
{
	OcspClient::OcspBuff  binary;
	OcspClient::OcspBuff  base64;
	OcspClient::OcspBuff  pathbuffer;
	std::string path(path_);

	if (host_.length() <= 0)
	{
		return;
	}

	if (conn_ != NULL)
	{
		return;
	}

	int32_t rc = stapling_issuer(cert);
	if (rc < 0)
	{
		return;
	}
	cert_ = cert;


	OCSP_REQUEST* ocsp = OCSP_REQUEST_new();
	if (ocsp == NULL) 
	{
		errx(1,"OCSP_REQUEST_new() failed");
		return;
	}

	OCSP_CERTID* id = OCSP_cert_to_id(NULL, cert, issuer_);
	if (id == NULL)
	{
		errx(1,"OCSP_cert_to_id() failed");
		goto failed;
	}

	if (OCSP_request_add0_id(ocsp, id) == NULL)
	{
		errx(1,"OCSP_request_add0_id() failed");
		OCSP_CERTID_free(id);
		goto failed;
	}

	int len = i2d_OCSP_REQUEST(ocsp, NULL);
	if (len <= 0) 
	{
		errx(1,"i2d_OCSP_REQUEST() failed");
		goto failed;
	}

	binary.resize(len);
	unsigned char*	data = binary.data();
	len = i2d_OCSP_REQUEST(ocsp, &data);
	if (len <= 0)
	{
		errx(1,"i2d_OCSP_REQUEST() failed");
		goto failed;
	}

	size_t b64len = base64_encoded_length(binary.size());
	base64.resize(b64len);

	encode_base64(base64, binary, basis64, 1);

	uintptr_t escape = escape_uri(NULL, base64.data(), base64.size(), OCSP_ESCAPE_URI_COMPONENT);


	std::copy(path.c_str(), path.c_str() + path.length(), back_inserter(pathbuffer));
	if (pathbuffer[pathbuffer.size()-1] != '/')
	{
		pathbuffer.push_back('/');
	}

	if (escape == 0) 
	{
		pathbuffer.resize(pathbuffer.size() + base64.size());
		memcpy(pathbuffer.data(), base64.data(), base64.size());
	}
	else 
	{
		pathbuffer.resize(pathbuffer.size() + base64.size() + 2 * escape);
		escape_uri(pathbuffer.data(), base64.data(), base64.size(),
			OCSP_ESCAPE_URI_COMPONENT);
	}

	path.append((char*)pathbuffer.data(), pathbuffer.size());

	warnx("%s ocsp request responder:%s size:%d",
		commonName(cert).c_str(),
		reponder_.c_str(),
		path.length());

	launch_request(path);

failed:
	OCSP_REQUEST_free(ocsp);
	return;
}


void OcspClient::launch_request(std::string& path)
{


	bev_ = bufferevent_socket_new(
		event_.getEventBase(),
		-1,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS);

	conn_ = evhttp_connection_base_bufferevent_new(
		event_.getEventBase(),
		NULL,
		bev_,
		host_.c_str(),
		port_);

	evhttp_connection_set_timeout(conn_, timeout_sec);
	if (retry_max > 0)
	{
		evhttp_connection_set_retries(conn_, retry_max);
	}

	request_ = evhttp_request_new(request_finished, this);

	struct evkeyvalq *request_headers =
		evhttp_request_get_output_headers(request_);
	evhttp_add_header(request_headers, "Host", host_.c_str());
	evhttp_add_header(request_headers, "Connection", "close");

	int suc = evhttp_make_request(conn_, request_, EVHTTP_REQ_GET, path.c_str());
	if (suc != 0)
	{
		errx(1,"evhttp_make_request returned %d\n", suc);
	}
}

void OcspClient::finish(
	struct evhttp_request *req,
	const int errcode)
{
	if(req == NULL)
	{
		warnx("socket error = %s (%d)\n",
			evutil_socket_error_to_string(errcode),
			errcode);
		return;
	}

	const int code = evhttp_request_get_response_code(req);

	if (code != HTTP_OK)
	{
		warnx("HTTP code=%d OCSP GET Request Failed err:%s(%d)", 
				code,
				evutil_socket_error_to_string(errcode),
				errcode);
		return;
	}

	struct evbuffer *buf = evhttp_request_get_input_buffer(req);
	size_t	len = evbuffer_get_length(buf);
	ocsp_response_.resize(len);

	u_char*	payload = evbuffer_pullup(buf, len);
	update_response(payload, len);	
}


void OcspClient::update_response(
	const u_char*	buffer,
	size_t buflen)
{
	int					resp_status = 0;
	OCSP_BASICRESP*		basic = NULL;
	X509_STORE*			store = NULL;
	STACK_OF(X509)*		chain = NULL;
	OCSP_CERTID*		id = NULL;
	ASN1_GENERALIZEDTIME*	thisupdate = NULL;
	ASN1_GENERALIZEDTIME*	nextupdate = NULL;
	time_t				valid = 0;
	OCSP_RESPONSE* ocsp = NULL;

	ocsp = d2i_OCSP_RESPONSE(NULL, &buffer, buflen);
	if (ocsp == NULL) {
		warnx("d2i_OCSP_RESPONSE() failed");
		goto error;
	}

	resp_status = OCSP_response_status(ocsp);

	if (resp_status != OCSP_RESPONSE_STATUS_SUCCESSFUL)
	{
		warnx("OCSP response not successful (%d: %s)",
			resp_status, OCSP_response_status_str(resp_status));
		goto error;
	}

	basic = OCSP_response_get1_basic(ocsp);
	if (basic == NULL) 
	{
		warnx("OCSP_response_get1_basic() failed");
		goto error;
	}

	store = SSL_CTX_get_cert_store(ssl_ctx_);
	if (store == NULL)
	{
		warnx("SSL_CTX_get_cert_store() failed");
		goto error;
	}

#ifdef SSL_CTRL_SELECT_CURRENT_CERT
	/* OpenSSL 1.0.2+ */
	SSL_CTX_select_current_cert(ssl_ctx_, cert_);
#endif

#ifdef SSL_CTRL_GET_EXTRA_CHAIN_CERTS
	/* OpenSSL 1.0.1+ */
	SSL_CTX_get_extra_chain_certs(ssl_ctx_, &chain);
#else
	chain = ssl_ctx_->extra_certs;
#endif

	if (OCSP_basic_verify(basic, chain, store,
		verify_ ? OCSP_TRUSTOTHER : OCSP_NOVERIFY)
		!= 1)
	{
		warnx("OCSP_basic_verify() failed");
		goto error;
	}

	id = OCSP_cert_to_id(NULL, cert_, issuer_);
	if (id == NULL)
	{
		warnx("OCSP_cert_to_id() failed");
		goto error;
	}

	if (OCSP_resp_find_status(basic, id, &resp_status, NULL, NULL,
		&thisupdate, &nextupdate)
		!= 1)
	{
		warnx("certificate status not found in the OCSP response");
		goto error;
	}

	if (resp_status != V_OCSP_CERTSTATUS_GOOD)
	{
		warnx("certificate status \"%s\" in the OCSP response",
					OCSP_cert_status_str(resp_status));
		goto error;
	}

	if (OCSP_check_validity(thisupdate, nextupdate, 300, -1) != 1) 
	{
		warnx("OCSP_check_validity() failed");
		goto error;
	}

	if (nextupdate)
	{
		valid = stapling_time(nextupdate);
		if (valid == (time_t)-1) 
		{
			warnx("invalid nextUpdate time in certificate status");
			goto error;
		}

	}

	write_response(ocsp);

	OCSP_CERTID_free(id);
	OCSP_BASICRESP_free(basic);
	OCSP_RESPONSE_free(ocsp);

	id = NULL;
	basic = NULL;
	ocsp = NULL;

	/* copy the response to memory not in ctx->pool */
	ocsp_response_.resize(buflen);
	memcpy(ocsp_response_.data(), buffer, buflen);

	warnx("ssl ocsp response, %s, %u",
		OCSP_cert_status_str(resp_status), buflen);

	return;

error:
	if (id)
	{
		OCSP_CERTID_free(id);
	}

	if (basic)
	{
		OCSP_BASICRESP_free(basic);
	}

	if (ocsp)
	{
		OCSP_RESPONSE_free(ocsp);
	}
}

void OcspClient::write_response(
	OCSP_RESPONSE* response)
{
	if (response_file_.length() <= 0)
	{
		return;
	}

	BIO* bio = BIO_new_file(response_file_.c_str(), "wb");
	if (bio == NULL)
	{
		warnx("ocsp response BIO_new_file(\"%s\", w) failed",
			response_file_.c_str());
		return;
	}

#if 0
	int writebyte = BIO_write(bio, ocsp_response_.data(), ocsp_response_.size());
	BIO_free(bio);
	if (writebyte <= 0)
	{
		warnx("ocsp response write(\"%s\") failed",
			response_file_.c_str());
	}
	return;
#else
	//	i2d_OCSP_RESPONSE_bio(bio, ocsp);
	OcspClient::OcspBuff resp;

	int len = i2d_OCSP_RESPONSE(response, NULL);
	if (len <= 0)
	{
		warnx("i2d_OCSP_RESPONSE(\"%s\") failed",
			response_file_.c_str());
		goto failed;
	}

	resp.resize(len);
	unsigned char* buf = resp.data();

	len = i2d_OCSP_RESPONSE(response, &buf);
	if (len <= 0)
	{
		warnx("i2d_OCSP_RESPONSE(\"%s\") failed",
			response_file_.c_str());
		goto failed;
	}

	int writebyte = BIO_write(bio, resp.data(), resp.size());
	if (writebyte <= 0)
	{
		warnx("ocsp response write(\"%s\") failed",
			response_file_.c_str());
	}

failed:
	BIO_free(bio);
	return;
#endif
}


time_t OcspClient::stapling_time(ASN1_GENERALIZEDTIME *asn1time)
{

	/*
	 * OpenSSL doesn't provide a way to convert ASN1_GENERALIZEDTIME
	 * into time_t.  To do this, we use ASN1_GENERALIZEDTIME_print(),
	 * which uses the "MMM DD HH:MM:SS YYYY [GMT]" format (e.g.,
	 * "Feb  3 00:55:52 2015 GMT"), and parse the result.
	 */

	BIO* bio = BIO_new(BIO_s_mem());
	if (bio == NULL)
	{
		return -1;
	}

	/* fake weekday prepended to match C asctime() format */

	BIO_write(bio, "Tue ", sizeof("Tue ") - 1);
	ASN1_GENERALIZEDTIME_print(bio, asn1time);

	char    *value = NULL;
	size_t len = BIO_get_mem_data(bio, &value);

	time_t time = curl_getdate(value, NULL);

	BIO_free(bio);

	return time;
}

std::string OcspClient::commonName(X509 *x509)
{
	X509_NAME *subject = X509_get_subject_name(x509);

	int subject_position = 
			X509_NAME_get_index_by_NID(subject, NID_commonName, 0);

	X509_NAME_ENTRY *entry = NULL;
	if (subject_position != -1)
	{
		entry = X509_NAME_get_entry(subject, subject_position);
	}

	ASN1_STRING* d = X509_NAME_ENTRY_get_data(entry);

	std::string comname((char*)ASN1_STRING_data(d), ASN1_STRING_length(d));

	return comname;
}



void OcspClient::encode_base64(OcspBuff& dst, OcspBuff& src, const u_char *basis, uint8_t padding)
{
	size_t len = src.size();
	u_char* s = src.data();
	u_char* d = dst.data();

	while (len > 2) {
		*d++ = basis[(s[0] >> 2) & 0x3f];
		*d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
		*d++ = basis[((s[1] & 0x0f) << 2) | (s[2] >> 6)];
		*d++ = basis[s[2] & 0x3f];

		s += 3;
		len -= 3;
	}

	if (len) {
		*d++ = basis[(s[0] >> 2) & 0x3f];

		if (len == 1) {
			*d++ = basis[(s[0] & 3) << 4];
			if (padding) {
				*d++ = '=';
			}

		}
		else {
			*d++ = basis[((s[0] & 3) << 4) | (s[1] >> 4)];
			*d++ = basis[(s[1] & 0x0f) << 2];
		}

		if (padding) {
			*d++ = '=';
		}
	}

	dst.resize(d - dst.data());
}

uintptr_t OcspClient::escape_uri(u_char *dst, u_char *src, size_t size, uint8_t type)
{
	static u_char   hex[] = "0123456789ABCDEF";

	/* " ", "#", "%", "?", %00-%1F, %7F-%FF */

	static uint32_t   uri[] = {
		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

					/* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
		0x80000029, /* 1000 0000 0000 0000  0000 0000 0010 1001 */

					/* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
		0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

					/*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
		0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	};

	/* " ", "#", "%", "&", "+", "?", %00-%1F, %7F-%FF */

	static uint32_t   args[] = {
		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

					/* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
		0x88000869, /* 1000 1000 0000 0000  0000 1000 0110 1001 */

					/* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
		0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

					/*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
		0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	};

	/* not ALPHA, DIGIT, "-", ".", "_", "~" */

	static uint32_t   uri_component[] = {
		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

					/* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
		0xfc009fff, /* 1111 1100 0000 0000  1001 1111 1111 1111 */

					/* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
		0x78000001, /* 0111 1000 0000 0000  0000 0000 0000 0001 */

					/*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
		0xb8000001, /* 1011 1000 0000 0000  0000 0000 0000 0001 */

		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	};

	/* " ", "#", """, "%", "'", %00-%1F, %7F-%FF */

	static uint32_t   html[] = {
		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

					/* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
		0x000000ad, /* 0000 0000 0000 0000  0000 0000 1010 1101 */

					/* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
		0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

					/*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
		0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	};

	/* " ", """, "%", "'", %00-%1F, %7F-%FF */

	static uint32_t   refresh[] = {
		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

					/* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
		0x00000085, /* 0000 0000 0000 0000  0000 0000 1000 0101 */

					/* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
		0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

					/*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
		0x80000000, /* 1000 0000 0000 0000  0000 0000 0000 0000 */

		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */
		0xffffffff  /* 1111 1111 1111 1111  1111 1111 1111 1111 */
	};

	/* " ", "%", %00-%1F */

	static uint32_t   memcached[] = {
		0xffffffff, /* 1111 1111 1111 1111  1111 1111 1111 1111 */

					/* ?>=< ;:98 7654 3210  /.-, +*)( '&%$ #"!  */
		0x00000021, /* 0000 0000 0000 0000  0000 0000 0010 0001 */

					/* _^]\ [ZYX WVUT SRQP  ONML KJIH GFED CBA@ */
		0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

					/*  ~}| {zyx wvut srqp  onml kjih gfed cba` */
		0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */

		0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
		0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
		0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
		0x00000000, /* 0000 0000 0000 0000  0000 0000 0000 0000 */
	};

	/* mail_auth is the same as memcached */

	static uint32_t  *map[] =
	{ uri, args, uri_component, html, refresh, memcached, memcached };


	uint32_t* escape = map[type];

	if (dst == NULL) {

		/* find the number of the characters to be escaped */

		uintptr_t n = 0;

		while (size) {
			if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
				n++;
			}
			src++;
			size--;
		}

		return n;
	}

	while (size) {
		if (escape[*src >> 5] & (1U << (*src & 0x1f))) {
			*dst++ = '%';
			*dst++ = hex[*src >> 4];
			*dst++ = hex[*src & 0xf];
			src++;

		}
		else {
			*dst++ = *src++;
		}
		size--;
	}

	return (uintptr_t)dst;
}

