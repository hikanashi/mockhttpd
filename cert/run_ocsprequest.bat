@echo off

rem 証明書作成ディレクトリ
set CERTDIR="cert"

rem OpenSSLディレクトリ
set OPENSSLCMD=C:\opt\local\bin\openssl.exe

set OCSPURL=http://localhost
set OCSPPORT=8888
set OCSPRESPONSE=ocsp_resp.der

set SCRIPTDIR=%~dp0

rem 中間CA(ica=Intermediate CA)設定
set INMDCACRT=icacrt.pem
set INMDCAJOIN=rootCA.pem

rem サーバ証明書設定
set SVR1CRT=svr1crt.pem
set SVR1JOIN=svr1CA.pem


if not exist %CERTDIR% (
	mkdir %CERTDIR%
)

cd %CERTDIR%

%OPENSSLCMD% ocsp -no_nonce -issuer %INMDCACRT% -cert %SVR1CRT% -CAfile %INMDCAJOIN% -url %OCSPURL% -port %OCSPPORT% -respout %OCSPRESPONSE%

:SUCCESS
echo "Successfully."
goto END


:FAILURE
echo "ERROR STOP"

:END
pause