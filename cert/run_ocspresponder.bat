@echo off

rem �ؖ����쐬�f�B���N�g��
set CERTDIR="cert"

rem OpenSSL�f�B���N�g��
set OPENSSLCMD=C:\opt\local\bin\openssl.exe

set OCSPPORT=8888

rem ����CA(ica=Intermediate CA)�ݒ�
set INMDCACRT=icacrt.pem
set INMDCAKEY=icakey.pem
set INMDCAJOIN=rootCA.pem

if not exist %CERTDIR% (
	mkdir %CERTDIR%
)

cd %CERTDIR%

%OPENSSLCMD% ocsp -ignore_err -index index.txt -CA %INMDCAJOIN% -rsigner %INMDCACRT% -rkey %INMDCAKEY% -port %OCSPPORT% -nrequest 1
if %ERRORLEVEL% NEQ 0 goto FAILURE

:SUCCESS
echo "Successfully."
goto END


:FAILURE
echo "ERROR STOP"

:END
rem pause