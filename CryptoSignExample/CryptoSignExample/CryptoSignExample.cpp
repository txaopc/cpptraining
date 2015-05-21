// CryptoSignExample.cpp : Defines the entry point for the console application.
//
#include "stdafx.h"
#include <stdio.h>
#include <conio.h>
#include <tchar.h>
#include <windows.h>
#include <wincrypt.h>
#include <stdlib.h>

#pragma comment(lib, "crypt32.lib")

#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

#define SIGNER_NAME L"Phạm Công Thảo"
//"31922e438e3dc1427c5662f11ab97dc89b66900f"
#define SIGNER_HASH "f0442490cdd7aa1d04b90fee44afca187a035177" 

#define CERT_STORE_NAME  L"MY"

int char2int(char input);
void hex2bin(const char* src, char* target);
void MyHandleError(LPTSTR psz);
bool SignMessage(CRYPT_DATA_BLOB *pSignedMessageBlob, CRYPT_HASH_BLOB *pSignerHash);
bool SignMessage2(CRYPT_DATA_BLOB *pSignedMessageBlob, CRYPT_HASH_BLOB *pSignerHash);
bool VerifySignedMessage(
    CRYPT_DATA_BLOB *pSignedMessageBlob, 
    CRYPT_DATA_BLOB *pDecodedMessageBlob);

int _tmain(int argc, _TCHAR* argv[])
{
	UNREFERENCED_PARAMETER(argc);
    UNREFERENCED_PARAMETER(argv);
    
    CRYPT_DATA_BLOB SignedMessage;

	char *hash=new char(20);
	hex2bin(SIGNER_HASH, hash);

	CRYPT_HASH_BLOB cert_hash;
	cert_hash.cbData = strlen((char*)hash);
	cert_hash.pbData = (BYTE*)hash;

    if(SignMessage2(&SignedMessage, &cert_hash))
    {
        CRYPT_DATA_BLOB DecodedMessage;

        if(VerifySignedMessage(&SignedMessage, &DecodedMessage))
        {
            free(DecodedMessage.pbData);
        }

        free(SignedMessage.pbData);
    }

    _tprintf(TEXT("Press any key to exit."));
    _getch();

	return 0;
}

int char2int(char input)
{
  if(input >= '0' && input <= '9')
    return input - '0';
  if(input >= 'A' && input <= 'F')
    return input - 'A' + 10;
  if(input >= 'a' && input <= 'f')
    return input - 'a' + 10;
  return 0;
}

void hex2bin(const char* src, char* target)
{
  while(*src && src[1])
  {
    *(target++) = char2int(*src)*16 + char2int(src[1]);
    src += 2;
  }
}

void MyHandleError(LPTSTR psz)
{
    _ftprintf(stderr, TEXT("An error occurred in the program. \n"));
    _ftprintf(stderr, TEXT("%s\n"), psz);
    _ftprintf(stderr, TEXT("Error number %x.\n"), GetLastError());
    _ftprintf(stderr, TEXT("Program terminating. \n"));
}

bool SignMessage2(CRYPT_DATA_BLOB *pSignedMessageBlob, CRYPT_HASH_BLOB *pSignerHash){
	bool fResult = false;
	BYTE* pbMessage;
	DWORD cbMessage;
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT pSignerCert;
	CRYPT_SIGN_MESSAGE_PARA SigParams;
	DWORD cbSignedMessageBlob;
	BYTE* pbSignedMessageBlob = NULL;

	pSignedMessageBlob->cbData = 0;
	pSignedMessageBlob->pbData=NULL;

	pbMessage = (BYTE*)TEXT("Cong hoa xa hoi chu nghia Viet Nam");
	cbMessage = (lstrlen((TCHAR*)pbMessage) + 1) * sizeof(TCHAR);

	const BYTE* MessageArray[] = {pbMessage};
	DWORD_PTR MessageSizeArray[1];
	MessageSizeArray[0] = cbMessage;

	_tprintf(TEXT("The message to be signed is \"%s\".\n"), pbMessage);

	if(!(hCertStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		CERT_STORE_NAME))){
			MyHandleError(TEXT("The MY store could not be opened."));
			goto exit_SignMessage;
	}

	if(pSignerCert = CertFindCertificateInStore(
       hCertStore,
       MY_ENCODING_TYPE,
       0,
	   CERT_FIND_HASH,
       pSignerHash,
       NULL))
    {
       _tprintf(TEXT("The signer's certificate was found.\n"));
    }
    else
    {
        MyHandleError( TEXT("Signer certificate not found."));
        goto exit_SignMessage;
    }

	//memset(&SigParams, 0, sizeof(SigParams));
	SigParams.cbSize = sizeof(SigParams);
	SigParams.dwMsgEncodingType = MY_ENCODING_TYPE;
	SigParams.pSigningCert = pSignerCert;
    SigParams.HashAlgorithm.pszObjId = szOID_RSA_SHA1RSA;
    SigParams.HashAlgorithm.Parameters.cbData = 0;
    SigParams.cMsgCert = 1;
    SigParams.rgpMsgCert = &pSignerCert;
    SigParams.cAuthAttr = 0;
    SigParams.dwInnerContentType = 0;
    SigParams.cMsgCrl = 0;
    SigParams.cUnauthAttr = 0;
    SigParams.dwFlags = 0;
    SigParams.pvHashAuxInfo = NULL;
    SigParams.rgAuthAttr = NULL;	
		
	HCRYPTPROV hCryptProv;
	DWORD nKeySpec;
	BOOL bFreeNeeded;


	// First, get the size of the signed BLOB.
	if(CryptSignMessage(
        &SigParams,
        FALSE,
        1,
        MessageArray,
        MessageSizeArray,
        NULL,
        &cbSignedMessageBlob))
    {
        _tprintf(TEXT("%d bytes needed for the encoded BLOB.\n"),
            cbSignedMessageBlob);
    }
    else
    {
        MyHandleError(TEXT("Getting signed BLOB size failed"));
        goto exit_SignMessage;
    }

	if (!CryptAcquireCertificatePrivateKey(pSignerCert,
                                          CRYPT_ACQUIRE_CACHE_FLAG,
                                          NULL,
                                          &hCryptProv,
										  &nKeySpec,
										  &bFreeNeeded))
	{	
        MyHandleError(TEXT("CryptAcquireCertificatePrivateKey failed"));
        goto exit_SignMessage;
    }

	CMSG_SIGNER_ENCODE_INFO aSignerInfo;
	memset(&aSignerInfo, 0, sizeof(aSignerInfo));

	aSignerInfo.cbSize = sizeof(aSignerInfo);
	aSignerInfo.pCertInfo = pSignerCert->pCertInfo;
	aSignerInfo.hCryptProv = hCryptProv;
	aSignerInfo.dwKeySpec = nKeySpec;
	aSignerInfo.HashAlgorithm.pszObjId = szOID_RSA_SHA1RSA;
	aSignerInfo.HashAlgorithm.Parameters.cbData = 0;

	CMSG_SIGNED_ENCODE_INFO aSignedInfo;
	memset(&aSignedInfo, 0, sizeof(aSignedInfo));
	aSignedInfo.cbSize = sizeof(aSignedInfo);
	aSignedInfo.cSigners = 1;
	aSignedInfo.rgSigners = &aSignerInfo;

	CERT_BLOB aCertBlob;
	aCertBlob.cbData = pSignerCert->cbCertEncoded;
	aCertBlob.pbData = pSignerCert->pbCertEncoded;

	aSignedInfo.cCertEncoded = 1;
	aSignedInfo.rgCertEncoded = &aCertBlob;

	HCRYPTMSG hMsg;
	if (!(hMsg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
									 CMSG_DETACHED_FLAG,
									 CMSG_SIGNED,
									 &aSignedInfo,
									 NULL,
									 NULL)))
	{
		MyHandleError(TEXT("CryptMsgOpenToEncode failed"));
        goto exit_SignMessage;
	}	

	// Allocate memory for the signed BLOB.
    if(!(pbSignedMessageBlob = 
       (BYTE*)malloc(cbSignedMessageBlob)))
    {
        MyHandleError(
            TEXT("Memory allocation error while signing."));
        goto exit_SignMessage;
    }

	// Get the signed message BLOB.
    if(CryptSignMessage(
          &SigParams,
          FALSE,
          1,
          MessageArray,
          MessageSizeArray,
          pbSignedMessageBlob,
          &cbSignedMessageBlob))
    {
        _tprintf(TEXT("The message was signed successfully. \n"));

        // pbSignedMessageBlob now contains the signed BLOB.
        fResult = true;
    }
    else
    {
        MyHandleError(TEXT("Error getting signed BLOB"));
        goto exit_SignMessage;
    }

	
	CRYPT_TIMESTAMP_PARA aTsPara;

	unsigned int nNonce = rand();
	aTsPara.pszTSAPolicyId = NULL;
	aTsPara.fRequestCerts = TRUE;
	aTsPara.Nonce.cbData = sizeof(nNonce);
	aTsPara.Nonce.pbData = (BYTE *)&nNonce;
	aTsPara.cExtension = 0;
	aTsPara.rgExtension = NULL;
	PCRYPT_TIMESTAMP_CONTEXT pTsContext = NULL;
	//http://tsa.safecreative.org/

	if(!CryptRetrieveTimeStamp(L"http://ca.gov.vn/tsa",
		0,
		0,
		szOID_OIWSEC_sha1,
		&aTsPara,
		pbSignedMessageBlob,
		cbSignedMessageBlob,
		&pTsContext,
		NULL,
		NULL)){
		MyHandleError(TEXT("CryptRetrieveTimeStamp failed: %d", GetLastError()));
		goto exit_SignMessage;
	}



	HCRYPTMSG hDecodedMsg;
	if (!(hDecodedMsg = CryptMsgOpenToDecode(PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
											CMSG_DETACHED_FLAG,
											CMSG_SIGNED, 
											NULL, 
											NULL,
											NULL))){

	}

exit_SignMessage:
	// Clean up and free memory as needed.
    if(pSignerCert)
    {
        CertFreeCertificateContext(pSignerCert);
    }
    
    if(hCertStore)
    {
        CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
        hCertStore = NULL;
    }

    // Only free the signed message if a failure occurred.
    if(!fResult)
    {
        if(pbSignedMessageBlob)
        {
            free(pbSignedMessageBlob);
            pbSignedMessageBlob = NULL;
        }
    }

    if(pbSignedMessageBlob)
    {
        pSignedMessageBlob->cbData = cbSignedMessageBlob;
        pSignedMessageBlob->pbData = pbSignedMessageBlob;
    }
    
    return fResult;
}

bool SignMessage(CRYPT_DATA_BLOB *pSignedMessageBlob, CRYPT_HASH_BLOB *pSignerHash){
	bool fResult = false;
	BYTE* pbMessage;
	DWORD cbMessage;
	HCERTSTORE hCertStore = NULL;
	PCCERT_CONTEXT pSignerCert;
	CRYPT_SIGN_MESSAGE_PARA SigParams;
	DWORD cbSignedMessageBlob;
	BYTE* pbSignedMessageBlob = NULL;

	pSignedMessageBlob->cbData = 0;
	pSignedMessageBlob->pbData=NULL;

	pbMessage = (BYTE*)TEXT("Cong hoa xa hoi chu nghia Viet Nam");
	cbMessage = (lstrlen((TCHAR*)pbMessage) + 1) * sizeof(TCHAR);

	const BYTE* MessageArray[] = {pbMessage};
	DWORD_PTR MessageSizeArray[1];
	MessageSizeArray[0] = cbMessage;

	_tprintf(TEXT("The message to be signed is \"%s\".\n"), pbMessage);

	if(!(hCertStore = CertOpenStore(
		CERT_STORE_PROV_SYSTEM,
		0,
		NULL,
		CERT_SYSTEM_STORE_CURRENT_USER,
		CERT_STORE_NAME))){
			MyHandleError(TEXT("The MY store could not be opened."));
			goto exit_SignMessage;
	}

	if(pSignerCert = CertFindCertificateInStore(
       hCertStore,
       MY_ENCODING_TYPE,
       0,
	   CERT_FIND_HASH,
       pSignerHash,
       NULL))
    {
       _tprintf(TEXT("The signer's certificate was found.\n"));
    }
    else
    {
        MyHandleError( TEXT("Signer certificate not found."));
        goto exit_SignMessage;
    }

	 // Initialize the signature structure.
    SigParams.cbSize = sizeof(CRYPT_SIGN_MESSAGE_PARA);
    SigParams.dwMsgEncodingType = MY_ENCODING_TYPE;
    SigParams.pSigningCert = pSignerCert;
    SigParams.HashAlgorithm.pszObjId = szOID_RSA_SHA1RSA;
    SigParams.HashAlgorithm.Parameters.cbData = 0;
    SigParams.cMsgCert = 1;
    SigParams.rgpMsgCert = &pSignerCert;
    SigParams.cAuthAttr = 0;
    SigParams.dwInnerContentType = 0;
    SigParams.cMsgCrl = 0;
    SigParams.cUnauthAttr = 0;
    SigParams.dwFlags = 0;
    SigParams.pvHashAuxInfo = NULL;
    SigParams.rgAuthAttr = NULL;
	SigParams.rgUnauthAttr = NULL;

	// First, get the size of the signed BLOB.
	if(CryptSignMessage(
        &SigParams,
        FALSE,
        1,
        MessageArray,
        MessageSizeArray,
        NULL,
        &cbSignedMessageBlob))
    {
        _tprintf(TEXT("%d bytes needed for the encoded BLOB.\n"),
            cbSignedMessageBlob);
    }
    else
    {
        MyHandleError(TEXT("Getting signed BLOB size failed"));
        goto exit_SignMessage;
    }

	// Allocate memory for the signed BLOB.
    if(!(pbSignedMessageBlob = 
       (BYTE*)malloc(cbSignedMessageBlob)))
    {
        MyHandleError(
            TEXT("Memory allocation error while signing."));
        goto exit_SignMessage;
    }

	// Get the signed message BLOB.
    if(CryptSignMessage(
          &SigParams,
          FALSE,
          1,
          MessageArray,
          MessageSizeArray,
          pbSignedMessageBlob,
          &cbSignedMessageBlob))
    {
        _tprintf(TEXT("The message was signed successfully. \n"));

        // pbSignedMessageBlob now contains the signed BLOB.
        fResult = true;
    }
    else
    {
        MyHandleError(TEXT("Error getting signed BLOB"));
        goto exit_SignMessage;
    }

	PCRYPT_TIMESTAMP_CONTEXT ppTsContext = new CRYPT_TIMESTAMP_CONTEXT();
	PCCERT_CONTEXT *ppTsSigner = NULL;
	HCERTSTORE *phStore = NULL;

	CRYPT_TIMESTAMP_PARA aTsPara;
	unsigned int nNonce = rand();
	aTsPara.pszTSAPolicyId = NULL;
	aTsPara.fRequestCerts = TRUE;
	aTsPara.Nonce.cbData = sizeof(nNonce);
	aTsPara.Nonce.pbData = (BYTE *)&nNonce;
	aTsPara.cExtension = 0;
	aTsPara.rgExtension = NULL;

	if(CryptRetrieveTimeStamp(
		L"http://ca.gov.vn/tsa",
		TIMESTAMP_NO_AUTH_RETRIEVAL,
		0,
		szOID_RSA_SHA1RSA, //szOID_OIWSEC_sha1 //szOID_RSA_SHA1RSA //szOID_NIST_sha256
		&aTsPara,
		pSignerHash->pbData, // array returned from CryptSignMessage
		pSignerHash->cbData, // length of array from CryptSignMessage
		&ppTsContext,
		NULL,//ppTsSigner,
		NULL)){
		_tprintf(TEXT("The message was timestamped successfully. \n"));
	}else {
		//GetLastError();
		_tprintf(TEXT("Timestamp failed. %d \n", GetLastError()));
	}

	delete ppTsContext;

exit_SignMessage:
	// Clean up and free memory as needed.
    if(pSignerCert)
    {
        CertFreeCertificateContext(pSignerCert);
    }
    
    if(hCertStore)
    {
        CertCloseStore(hCertStore, CERT_CLOSE_STORE_CHECK_FLAG);
        hCertStore = NULL;
    }

    // Only free the signed message if a failure occurred.
    if(!fResult)
    {
        if(pbSignedMessageBlob)
        {
            free(pbSignedMessageBlob);
            pbSignedMessageBlob = NULL;
        }
    }

    if(pbSignedMessageBlob)
    {
        pSignedMessageBlob->cbData = cbSignedMessageBlob;
        pSignedMessageBlob->pbData = pbSignedMessageBlob;
    }
    
    return fResult;
}

bool VerifySignedMessage(
    CRYPT_DATA_BLOB *pSignedMessageBlob, 
    CRYPT_DATA_BLOB *pDecodedMessageBlob)
{
	bool fReturn = false;
    DWORD cbDecodedMessageBlob;
    BYTE *pbDecodedMessageBlob = NULL;
    CRYPT_VERIFY_MESSAGE_PARA VerifyParams;

	// Initialize the output.
    pDecodedMessageBlob->cbData = 0;
    pDecodedMessageBlob->pbData = NULL;

	// Initialize the VerifyParams data structure.
    VerifyParams.cbSize = sizeof(CRYPT_VERIFY_MESSAGE_PARA);
    VerifyParams.dwMsgAndCertEncodingType = MY_ENCODING_TYPE;
    VerifyParams.hCryptProv = 0;
    VerifyParams.pfnGetSignerCertificate = NULL;
    VerifyParams.pvGetArg = NULL;
	

	// First, call CryptVerifyMessageSignature to get the length 
    // of the buffer needed to hold the decoded message.
    if(CryptVerifyMessageSignature(
        &VerifyParams,
        0,
        pSignedMessageBlob->pbData,
        pSignedMessageBlob->cbData,
        NULL,
        &cbDecodedMessageBlob,
        NULL))
    {
        _tprintf(TEXT("%d bytes needed for the decoded message.\n"),
            cbDecodedMessageBlob);

    }
    else
    {
        _tprintf(TEXT("Verification message failed. \n"));
        goto exit_VerifySignedMessage;
    }

	//---------------------------------------------------------------
    //   Allocate memory for the decoded message.
    if(!(pbDecodedMessageBlob = 
       (BYTE*)malloc(cbDecodedMessageBlob)))
    {
        MyHandleError(
            TEXT("Memory allocation error allocating decode BLOB."));
        goto exit_VerifySignedMessage;
    }

	//---------------------------------------------------------------
    // Call CryptVerifyMessageSignature again to verify the signature
    // and, if successful, copy the decoded message into the buffer. 
    // This will validate the signature against the certificate in 
    // the local store.
    if(CryptVerifyMessageSignature(
        &VerifyParams,
        0,
        pSignedMessageBlob->pbData,
        pSignedMessageBlob->cbData,
        pbDecodedMessageBlob,
        &cbDecodedMessageBlob,
        NULL))
    {
        _tprintf(TEXT("The verified message is \"%s\".\n"),
            pbDecodedMessageBlob);

        fReturn = true;
    }
    else
    {
        _tprintf(TEXT("Verification message failed. \n"));
    }

	exit_VerifySignedMessage:
    // If something failed and the decoded message buffer was 
    // allocated, free it.
    if(!fReturn)
    {
        if(pbDecodedMessageBlob)
        {
            free(pbDecodedMessageBlob);
            pbDecodedMessageBlob = NULL;
        }
    }

    // If the decoded message buffer is still around, it means the 
    // function was successful. Copy the pointer and size into the 
    // output parameter.
    if(pbDecodedMessageBlob)
    {
        pDecodedMessageBlob->cbData = cbDecodedMessageBlob;
        pDecodedMessageBlob->pbData = pbDecodedMessageBlob;
    }

    return fReturn;
}

