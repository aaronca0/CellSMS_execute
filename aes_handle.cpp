#include "aes_handle.h"



byte key[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv[ CryptoPP::AES::BLOCKSIZE];
byte key2[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv2[ CryptoPP::AES::BLOCKSIZE];
byte key3[ CryptoPP::AES::DEFAULT_KEYLENGTH ], iv3[ CryptoPP::AES::BLOCKSIZE];

void initKV()
{
    memset( key, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv, 0x00, CryptoPP::AES::BLOCKSIZE );

	memset( key2, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv2, 0x00, CryptoPP::AES::BLOCKSIZE );

	memset( key3, 0x00, CryptoPP::AES::DEFAULT_KEYLENGTH );
    memset( iv3, 0x00, CryptoPP::AES::BLOCKSIZE );
	
    char tmpK[] = "1234567890123456";
    char tmpIV[] = "1234567890123456";

	 char tmpK2[] = "9584309082143267";
    char tmpIV2[] = "9584309082143267";

	 char tmpK3[] = "4721053027840529";
    char tmpIV3[] = "4721053027840529";
	
    for (int j = 0; j < CryptoPP::AES::DEFAULT_KEYLENGTH; ++j)
    {
        key[j] = tmpK[j];
    }
    for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; ++i)
    {
        iv[i] = tmpIV[i];
    }

	for (int j = 0; j < CryptoPP::AES::DEFAULT_KEYLENGTH; ++j)
    {
        key2[j] = tmpK2[j];
    }
    for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; ++i)
    {
        iv2[i] = tmpIV2[i];
    }

	for (int j = 0; j < CryptoPP::AES::DEFAULT_KEYLENGTH; ++j)
    {
        key3[j] = tmpK3[j];
    }
    for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; ++i)
    {
        iv3[i] = tmpIV3[i];
    }
}

string encrypt_Ex(char* pText,int id_x)
{
	string str;
	str.assign(pText);
	return encrypt(str,id_x);
}


string encrypt(string plainText,int idx)
{
    string cipherText;

    //
   
	if(idx==1)
	{
		 CryptoPP::AES::Encryption aesEncryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
   		 CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv );
		 CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( cipherText ));
   		 stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plainText.c_str() ), plainText.length() + 1 );
    		 stfEncryptor.MessageEnd();
	}
	else if(idx==2)
	{
		CryptoPP::AES::Encryption aesEncryption(key2, CryptoPP::AES::DEFAULT_KEYLENGTH);
   		 CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv2 );
		 CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( cipherText ));
   		 stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plainText.c_str() ), plainText.length() + 1 );
    		 stfEncryptor.MessageEnd();
	}
	else if(idx==3)
	{
		CryptoPP::AES::Encryption aesEncryption(key3, CryptoPP::AES::DEFAULT_KEYLENGTH);
   		 CryptoPP::CBC_Mode_ExternalCipher::Encryption cbcEncryption( aesEncryption, iv3 );
		 CryptoPP::StreamTransformationFilter stfEncryptor(cbcEncryption, new CryptoPP::StringSink( cipherText ));
   		 stfEncryptor.Put( reinterpret_cast<const unsigned char*>( plainText.c_str() ), plainText.length() + 1 );
    		 stfEncryptor.MessageEnd();
	}
	
    

    string cipherTextHex;
    for( int i = 0; i < cipherText.size(); i++ )
    {
        char ch[3] = {0};
        sprintf(ch, "%02x",  static_cast<byte>(cipherText[i]));
        cipherTextHex += ch;
    }

    return cipherTextHex;
}


string decrypt(string cipherTextHex,int idx)
{
    string cipherText;
    string decryptedText;

    int i = 0;
    while(true)
    {
        char c;
        int x;
        stringstream ss;
        ss<<hex<<cipherTextHex.substr(i, 2).c_str();
        ss>>x;
        c = (char)x;
        cipherText += c;
        if(i >= cipherTextHex.length() - 2)break;
        i += 2;
    }

    if(idx==1)
	{
		CryptoPP::AES::Decryption aesDecryption(key, CryptoPP::AES::DEFAULT_KEYLENGTH);
    		CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv );
    		CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedText ));
    		stfDecryptor.Put( reinterpret_cast<const unsigned char*>( cipherText.c_str() ), cipherText.size());
    		stfDecryptor.MessageEnd();
	}
	else if(idx==2)
	{
		CryptoPP::AES::Decryption aesDecryption(key2, CryptoPP::AES::DEFAULT_KEYLENGTH);
    		CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv2 );
    		CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedText ));
    		stfDecryptor.Put( reinterpret_cast<const unsigned char*>( cipherText.c_str() ), cipherText.size());
    		stfDecryptor.MessageEnd();
	}
	else if(idx==3)
	{
		CryptoPP::AES::Decryption aesDecryption(key3, CryptoPP::AES::DEFAULT_KEYLENGTH);
    		CryptoPP::CBC_Mode_ExternalCipher::Decryption cbcDecryption( aesDecryption, iv3 );
    		CryptoPP::StreamTransformationFilter stfDecryptor(cbcDecryption, new CryptoPP::StringSink( decryptedText ));
    		stfDecryptor.Put( reinterpret_cast<const unsigned char*>( cipherText.c_str() ), cipherText.size());
    		stfDecryptor.MessageEnd();
	}
    

    return decryptedText;
}

