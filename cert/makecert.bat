@echo off

rem 証明書作成ディレクトリ
set CERTDIR="cert"

rem OpenSSL作成ディレクトリ
set OPENSSLCMD=C:\opt\local\bin\openssl.exe

set SCRIPTDIR=%~dp0

rem openssl.cnf設定
set SERIALNO=01
set CRLNO=00
set CRLURI=http://localhost/revokecrl.pem
set OCSPURI=http://localhost:8887/
set DNSNAME=localhost

rem RootCA設定
set ROOTCASUBJ=/C=JP/ST=Tokyo/L=Roppongi/O=HogeSystems/OU=RCA/CN=rca.hogesystems.com
set ROOTCACRT=rcacrt.pem
set ROOTCAKEY=rcakey.pem
set ROOTCADAY=3650
set CRLDAY=3650
set ROOTCACRL=rcacrl.pem
set CRLJOIN=revokecrl.pem

rem 中間CA(ica=Intermediate CA)設定
set INMDCASUBJ=/C=JP/ST=Tokyo/L=Roppongi/O=HogeSystems/OU=ICA/CN=ica.hogesystems.com
set INMDCACRT=icacrt.pem
set INMDCAKEY=icakey.pem
set INMDCACSR=icacsr.pem
set INMDCADAY=1825
set INMDCACRL=icacrl.pem
set INMDCAJOIN=rootCA.pem

rem サーバ証明書設定
set SVR1SUBJ=/C=JP/ST=Tokyo/L=Roppongi/O=HogeSystems/OU=JTAC/CN=localhost
set SVR1CRT=svr1crt.pem
set SVR1KEY=svr1key.pem
set SVR1CSR=svr1csr.pem
set SVR1DAY=365
set SVR1JOIN=svr1CA.pem

rem サーバ証明書設定(Revoke用)
set SVR2SUBJ=/C=JP/ST=Tokyo/L=Roppongi/O=HogeSystems/OU=JTAC/CN=localhost2
set SVR2CRT=svr2crt.pem
set SVR2KEY=svr2key.pem
set SVR2CSR=svr2csr.pem
set SVR2DAY=365
set SVR2JOIN=svr2CA.pem


rem クライアント証明書設定
set CLI1SUBJ=/C=JP/ST=Tokyo/L=Roppongi/O=HogeSystems/OU=JTAC/CN=pc1.testexample.com
set CLI1CRT=pc1crt.pem
set CLI1KEY=pc1key.pem
set CLI1CSR=pc1csr.pem
set CLI1DAY=365
set CLI1JOIN=pc1CA.pem

rem クライアント証明書設定(Revoke用)
set CLI2SUBJ=/C=JP/ST=Tokyo/L=Roppongi/O=HogeSystems/OU=JTAC/CN=pc2.testexample.com
set CLI2CRT=pc2crt.pem
set CLI2KEY=pc2key.pem
set CLI2CSR=pc2csr.pem
set CLI2DAY=365
set CLI2JOIN=pc2CA.pem


if not exist %CERTDIR% (
	mkdir %CERTDIR%
)

cd %CERTDIR%


rem IDを生成
echo %SERIALNO% > serial
echo %CRLNO% > crlnumber

rem index.txt(空ファイル)を生成
type nul > index.txt

rem openssl.cnf 生成
(
echo.HOME			= .
echo.RANDFILE		= $ENV::HOME/.rnd
echo.
echo.[ ca ]
echo.default_ca	= CA_default		# The default ca section
echo.[ CA_default ]
echo.dir		= .
echo.database	= $dir/index.txt
echo.new_certs_dir	= $dir
echo.serial		= $dir/serial
echo.crlnumber	= $dir/crlnumber
echo.RANDFILE	= $dir/.rand	# private random number file
echo.x509_extensions	= usr_cert		# The extentions to add to the cert
echo.name_opt 	= ca_default		# Subject Name options
echo.cert_opt 	= ca_default		# Certificate field options
echo.crl_extensions	= crl_ext
echo.default_days	= %ROOTCADAY%
echo.default_crl_days= %CRLDAY%
echo.default_md	= default		# use public key default MD
echo.preserve	= no			# keep passed DN ordering
echo.policy		= policy_match
echo.[ policy_match ]
echo.countryName		= match
echo.stateOrProvinceName	= match
echo.organizationName	= match
echo.organizationalUnitName	= optional
echo.commonName		= supplied
echo.emailAddress		= optional
echo.
echo.[ req ]
echo.default_bits		= 2048
echo.distinguished_name	= req_distinguished_name
echo.x509_extensions	= rca
echo.string_mask = utf8only
echo.attributes		= req_attributes
echo.
echo.[ req_attributes ]
echo.challengePassword		= A challenge password
echo.challengePassword_min		= 0
echo.challengePassword_max		= 20
echo.
echo.[ req_distinguished_name ]
echo.
echo.[ usr_cert ]
echo.
echo.[ crl_ext ]
echo.authorityKeyIdentifier=keyid:always
echo.
echo.[ rca ]
echo.subjectKeyIdentifier=hash
echo.authorityKeyIdentifier=keyid:always,issuer
echo.basicConstraints = CA:true
echo.keyUsage = digitalSignature, cRLSign, keyCertSign
echo.
echo.[ ica ]
echo.subjectKeyIdentifier = hash
echo.authorityKeyIdentifier = keyid:always, issuer
echo.basicConstraints = CA:TRUE, pathlen:0
echo.keyUsage = digitalSignature, cRLSign, keyCertSign
echo.
echo.[ svr ]
echo.extendedKeyUsage = serverAuth
echo.nsComment			= "OpenSSL Generated Certificate"
echo.basicConstraints = CA:FALSE
echo.keyUsage = digitalSignature, keyEncipherment
echo.subjectKeyIdentifier = hash
echo.authorityKeyIdentifier = keyid, issuer
echo.crlDistributionPoints = URI:%CRLURI%
echo.authorityInfoAccess = OCSP;URI:%OCSPURI%
echo.subjectAltName = @alt_names
echo.[alt_names]
echo.DNS.1 = %DNSNAME%
echo.
echo.[ usr ]
echo.extendedKeyUsage = clientAuth, emailProtection
echo.nsComment			= "OpenSSL Generated Certificate"
echo.basicConstraints = CA:FALSE
echo.keyUsage = digitalSignature, keyEncipherment
echo.subjectKeyIdentifier = hash
echo.authorityKeyIdentifier = keyid, issuer
echo.crlDistributionPoints = URI:%CRLURI%
echo.authorityInfoAccess = OCSP;URI:%OCSPURI%
echo.
echo.[ ocsp ]
echo.basicConstraints = CA:FALSE
echo.subjectKeyIdentifier = hash
echo.authorityKeyIdentifier = keyid,issuer
echo.keyUsage = critical, digitalSignature, keyEncipherment, nonRepudiation
echo.extendedKeyUsage = critical, OCSPSigning
)>openssl.cfg
if %ERRORLEVEL% NEQ 0 goto FAILURE


rem RootCA作成
%OPENSSLCMD% genrsa 2048 > %ROOTCAKEY%
if %ERRORLEVEL% NEQ 0 goto FAILURE
%OPENSSLCMD% req -new -x509 -config openssl.cfg -extensions rca -newkey rsa:2048 -days %ROOTCADAY% -key %ROOTCAKEY% -subj "%ROOTCASUBJ%"  > %ROOTCACRT%
if %ERRORLEVEL% NEQ 0 goto FAILURE

FOR /F "usebackq tokens=*" %%i in (`%OPENSSLCMD% x509 -subject_hash -noout -in %ROOTCACRT%`) do @set HASHNAME=%%i
copy %ROOTCACRT% %HASHNAME%.0

rem 中間CA作成
%OPENSSLCMD% genrsa 2048 > %INMDCAKEY%
if %ERRORLEVEL% NEQ 0 goto FAILURE
%OPENSSLCMD% req -new -config openssl.cfg -sha256 -newkey rsa:2048 -key %INMDCAKEY% -subj "%INMDCASUBJ%" > %INMDCACSR%
if %ERRORLEVEL% NEQ 0 goto FAILURE
%OPENSSLCMD% ca -config openssl.cfg -notext -extensions ica -md sha256 -batch -days %INMDCADAY% -keyfile %ROOTCAKEY% -cert %ROOTCACRT%  -in %INMDCACSR% > %INMDCACRT%
if %ERRORLEVEL% NEQ 0 goto FAILURE
copy %INMDCACRT%+%ROOTCACRT% %INMDCAJOIN%
del %INMDCACSR%

FOR /F "usebackq tokens=*" %%i in (`%OPENSSLCMD% x509 -subject_hash -noout -in %INMDCACRT%`) do @set HASHNAME=%%i
copy %INMDCACRT% %HASHNAME%.0


rem サーバ証明書作成
%OPENSSLCMD% genrsa 2048 > %SVR1KEY%
if %ERRORLEVEL% NEQ 0 goto FAILURE
%OPENSSLCMD% req -new -config openssl.cfg -sha256 -newkey rsa:2048 -key %SVR1KEY% -subj "%SVR1SUBJ%" -out %SVR1CSR%
if %ERRORLEVEL% NEQ 0 goto FAILURE
%OPENSSLCMD% ca -config openssl.cfg -notext -extensions svr -md sha256 -batch -days %SVR1DAY% -keyfile %INMDCAKEY% -cert %INMDCACRT% -in %SVR1CSR% -out %SVR1CRT%
if %ERRORLEVEL% NEQ 0 goto FAILURE
copy %SVR1CRT%+%INMDCACRT% %SVR1JOIN%
if %ERRORLEVEL% NEQ 0 goto FAILURE
del %SVR1CSR%

FOR /F "usebackq tokens=*" %%i in (`%OPENSSLCMD% x509 -subject_hash -noout -in %SVR1CRT%`) do @set HASHNAME=%%i
copy %SVR1CRT% %HASHNAME%.0


%OPENSSLCMD% ecparam -out %SVR2KEY% -name prime256v1 -genkey
if %ERRORLEVEL% NEQ 0 goto FAILURE
%OPENSSLCMD% req -new  -config openssl.cfg -sha256 -outform PEM -keyform PEM -key %SVR2KEY% -subj "%SVR2SUBJ%" -out %SVR2CSR%
if %ERRORLEVEL% NEQ 0 goto FAILURE
%OPENSSLCMD% ca -config openssl.cfg -notext -extensions svr -md sha256 -batch -days %SVR2DAY% -keyfile %INMDCAKEY% -cert %INMDCACRT% -in %SVR2CSR% -out %SVR2CRT%
if %ERRORLEVEL% NEQ 0 goto FAILURE
copy %SVR2CRT%+%INMDCACRT% %SVR2JOIN%
if %ERRORLEVEL% NEQ 0 goto FAILURE
del %SVR2CSR%

FOR /F "usebackq tokens=*" %%i in (`%OPENSSLCMD% x509 -subject_hash -noout -in %SVR2CRT%`) do @set HASHNAME=%%i
copy %SVR2CRT% %HASHNAME%.0

rem クライアント証明書作成
%OPENSSLCMD% genrsa 2048 > %CLI1KEY%
if %ERRORLEVEL% NEQ 0 goto FAILURE
%OPENSSLCMD% req -new -config openssl.cfg -sha256 -newkey rsa:2048 -key %CLI1KEY% -subj "%CLI1SUBJ%" -out %CLI1CSR%
if %ERRORLEVEL% NEQ 0 goto FAILURE
%OPENSSLCMD% ca -config openssl.cfg -notext -extensions usr -md sha256 -batch -days %CLI1DAY% -keyfile %INMDCAKEY% -cert %INMDCACRT% -in %CLI1CSR% -out %CLI1CRT%
if %ERRORLEVEL% NEQ 0 goto FAILURE
copy %CLI1CRT%+%INMDCACRT% %CLI1JOIN%
del %CLI1CSR%


%OPENSSLCMD% genrsa 2048 > %CLI2KEY%
if %ERRORLEVEL% NEQ 0 goto FAILURE
%OPENSSLCMD% req -new -config openssl.cfg -sha256 -newkey rsa:2048 -key %CLI2KEY% -subj "%CLI2SUBJ%" -out %CLI2CSR%
if %ERRORLEVEL% NEQ 0 goto FAILURE
%OPENSSLCMD% ca -config openssl.cfg -notext -extensions usr -md sha256 -batch -days %CLI2DAY% -keyfile %INMDCAKEY% -cert %INMDCACRT% -in %CLI2CSR% -out %CLI2CRT%
if %ERRORLEVEL% NEQ 0 goto FAILURE
copy %CLI2CRT%+%INMDCACRT% %CLI2JOIN%
del %CLI2CSR%

rem 証明書をRevoke
%OPENSSLCMD% ca -config openssl.cfg -cert %ROOTCACRT% -keyfile %ROOTCAKEY% -revoke %CLI2CRT%
if %ERRORLEVEL% NEQ 0 goto FAILURE

%OPENSSLCMD% ca -config openssl.cfg -cert %ROOTCACRT% -keyfile %ROOTCAKEY% -revoke %SVR2CRT%
if %ERRORLEVEL% NEQ 0 goto FAILURE

rem CRL作成
%OPENSSLCMD%  ca -gencrl -config openssl.cfg -cert %INMDCACRT% -keyfile %INMDCAKEY% > %INMDCACRL%
if %ERRORLEVEL% NEQ 0 goto FAILURE

FOR /F "usebackq tokens=*" %%i in (`%OPENSSLCMD% crl -hash -noout -in %INMDCACRL%`) do @set HASHNAME=%%i
copy %INMDCACRL% %HASHNAME%.r0

rem %OPENSSLCMD%  ca -gencrl -config openssl.cfg -cert %ROOTCACRT% -keyfile %ROOTCAKEY% > %ROOTCACRL%
rem if %ERRORLEVEL% NEQ 0 goto FAILURE
rem copy %INMDCACRL%+%ROOTCACRL% %CRLJOIN%

:SUCCESS
echo "Successfully."
goto END


:FAILURE
echo "ERROR STOP"

:END
pause