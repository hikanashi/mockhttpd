#ifndef OCSPCLIENT_H_
#define OCSPCLIENT_H_

#include "Common.h"
#include <vector>
#include <string>

#include "EventHandler.h"


class OcspClient
{
public:

	OcspClient(
		EventHandler&	ev,
		SSL_CTX*		ssl_ctx,
		X509*			cert);
	virtual ~OcspClient();

	int32_t init(
		std::string& response_file,
		bool stapling_verify);


	// callback functions
	int certificate_status(
		SSL* ssl);

	void	finish(
				struct evhttp_request *req, 
				const int errcode);

	void clear_request();

protected:
	typedef std::vector<unsigned char> OcspBuff;

	int32_t setup_stapling(
		std::string& res_file);

	int32_t stapling_file(
		std::string& res_file);

	int32_t stapling_certificate();

	int32_t stapling_issuer(
			X509*	cert);

	int32_t stapling_responder(
		X509*	cert);

	void stapling_update(
				X509*	cert);
	void encode_base64(
			OcspBuff& dst,
			OcspBuff& src,
			const u_char *basis,
			uint8_t padding);

	uintptr_t escape_uri(
			u_char *dst, 
			u_char *src,
			size_t size, 
			uint8_t type);

	void	launch_request(std::string& path);

	void update_response(
		const u_char*	buffer,
		size_t buflen);

	void write_response(
		OCSP_RESPONSE* response);

	time_t stapling_time(ASN1_GENERALIZEDTIME *asn1time);

	std::string commonName(X509 *x509);
private:
	EventHandler&				event_;
	struct evhttp_request*		request_ ;
	struct evhttp_connection*	conn_;
	struct bufferevent*			bev_;

	bool						verify_;
	SSL_CTX*					ssl_ctx_;
	X509*						cert_;
	X509*						issuer_;
	std::string					reponder_;

	std::string					host_;
	ev_uint16_t					port_;
	std::string					path_;
	int							timeout_sec;
	int							retry_max;
	OcspBuff 					ocsp_response_;
	std::string					response_file_;


};

#endif /* OCSPCLIENT_H_ */
