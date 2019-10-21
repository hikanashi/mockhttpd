@echo off

rem �ؖ����쐬�f�B���N�g��
set CERTDIR="cert"

rem OpenSSL�f�B���N�g��
set OPENSSLCMD=C:\opt\local\bin\openssl.exe

set OCSPHOST=localhost
set OCSPPORT=8888
set OCSPRESPONSE=ocsp_resp.der

set SCRIPTDIR=%~dp0

rem ����CA(ica=Intermediate CA)�ݒ�
set INMDCACRT=icacrt.pem
set INMDCAJOIN=rootCA.pem

rem �T�[�o�ؖ����ݒ�
set SVR1JOIN=svr1CA.pem


if not exist %CERTDIR% (
	mkdir %CERTDIR%
)

cd %CERTDIR%

%OPENSSLCMD% ocsp -no_nonce -issuer %INMDCACRT% -cert %SVR1JOIN% -CAfile %INMDCAJOIN% -host %OCSPHOST% -port %OCSPPORT% -respout %OCSPRESPONSE%

:SUCCESS
echo "Successfully."
goto END


:FAILURE
echo "ERROR STOP"

:END
pause