#include <scrypt/scrypt.hpp>
#include <scrypt/error.hpp>
#include <iostream>
#include <scrypt/sha1.hpp>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/pem.h>
#include <openssl/err.h>

namespace scrypt {
    RSA* get_pub( const char* key, uint32_t key_size, uint32_t pe )
    {
        RSA* rsa = RSA_new();
        rsa->n = BN_bin2bn( (unsigned char*)key, key_size, NULL );
        rsa->e = BN_new();
        BN_set_word(rsa->e, pe );
        return rsa;
    }
    RSA* get_priv( const std::vector<char>& d, uint32_t /*key_size*/, uint32_t /*pe*/ )
    {
        BIO* mem = (BIO*)BIO_new_mem_buf( (void*)&d.front(), d.size() );
        RSA* rsa = PEM_read_bio_RSAPrivateKey(mem, NULL, NULL, NULL );
        BIO_free(mem);
        return rsa;
    }

    bool verify_data( const char* key, uint32_t key_size, uint32_t pe, const sha1& digest, const char* sig )
    {
        RSA* pub = get_pub( key,key_size,pe);
        bool v = RSA_verify( NID_sha1, (const uint8_t*)digest.hash, 20, (uint8_t*)sig, key_size, pub );
        RSA_free(pub);
        return v;
    }
    bool sign_data( const std::vector<char>& key, uint32_t key_size, uint32_t pe, const sha1& digest, char* sig )
    {
        RSA* priv = get_priv( key,key_size,pe);
        if( !priv ) {
            error::generic g(scrypt::error::generic("Error loading private key:  " +  std::string(ERR_error_string( ERR_get_error(),NULL))) );
		        BOOST_THROW_EXCEPTION(g);
        }
        uint32_t slen = 0;
        if( 1 != RSA_sign( NID_sha1, (uint8_t*)digest.hash, sizeof(digest.hash), (unsigned char*)sig, &slen, priv ) )
        {
            RSA_free(priv);
            error::generic g(scrypt::error::generic("Error signing data: " +  std::string(ERR_error_string( ERR_get_error(),NULL))) );
		        BOOST_THROW_EXCEPTION(g);
                                                
        }
        RSA_free(priv);
        return true;
    }

    bool public_encrypt( const char* key, uint32_t key_size, uint32_t pe, const std::vector<char>& in, std::vector<char>& out )
    {
        RSA* pub = get_pub( key,key_size/8,pe);
        out.resize(RSA_size(pub));
        int rtn = RSA_public_encrypt( in.size(), (unsigned char*)&in.front(), (unsigned char*)&out.front(), pub, RSA_PKCS1_OAEP_PADDING );
        RSA_free(pub);
        if( rtn >= 0 )
        {
            out.resize(rtn);
            return true;
        }
        out.resize(0);
        BOOST_THROW_EXCEPTION( scrypt::error::generic( ERR_error_string( ERR_get_error(), NULL ) ) );
        return false;
    }
    bool public_decrypt( const char* key, uint32_t key_size, uint32_t pe, const std::vector<char>& in, std::vector<char>& out )
    {
        RSA* pub = get_pub( key,key_size/8,pe);
        out.resize(RSA_size(pub));
        int rtn = RSA_public_decrypt( RSA_size(pub), (unsigned char*)&in.front(), (unsigned char*)&out.front(), pub, RSA_PKCS1_OAEP_PADDING );
        RSA_free(pub);
        if( rtn >= 0 )
        {
            out.resize(rtn);
            return true;
        }
        out.resize(0);
        BOOST_THROW_EXCEPTION( scrypt::error::generic( ERR_error_string( ERR_get_error(), NULL ) ) );
        return false;;
    }
    bool private_encrypt( const std::vector<char>& key, uint32_t key_size, uint32_t pe, const std::vector<char>& in, std::vector<char>& out )
    {
        RSA* priv = get_priv( key,key_size/8,pe);
        int rtn = RSA_private_encrypt( in.size(), (unsigned char*)&in.front(), (unsigned char*)&out.front(), priv, RSA_PKCS1_OAEP_PADDING );
        RSA_free(priv);
        if( rtn >= 0 )
        {
            out.resize(rtn);
            return true;
        }
        out.resize(0);
        return false;;
    }
    bool private_decrypt( const std::vector<char>& key, uint32_t key_size, uint32_t pe, const std::vector<char>& in, std::vector<char>& out )
    {
        
        RSA* priv = get_priv( key,key_size/8,pe);
        out.resize(RSA_size(priv));
        int rtn = RSA_private_decrypt( in.size(), (unsigned char*)&in.front(), (unsigned char*)&out.front(), priv, RSA_PKCS1_OAEP_PADDING );
        RSA_free(priv);
        if( rtn >= 0 )
        {
            out.resize(rtn);
            return true;
        }
        out.resize(0);
        BOOST_THROW_EXCEPTION( scrypt::error::generic( ERR_error_string( ERR_get_error(), NULL ) ) );
        return false;
    }

    bool generate_keys( char* pubkey, std::vector<char>& privkey, uint32_t key_size, uint32_t pe )
    {
        static bool init = true;
        if( init ) { ERR_load_crypto_strings(); init = false; }

        RSA* rsa = RSA_generate_key( key_size, pe, NULL, NULL );
        BN_bn2bin( rsa->n, (unsigned char*)pubkey );

        BIO *mem = BIO_new(BIO_s_mem());
        int e = PEM_write_bio_RSAPrivateKey(mem, rsa,  NULL, NULL, 0, NULL, NULL ); 
        if( e != 1 )
        {
            BIO_free(mem);
            RSA_free(rsa);
		        BOOST_THROW_EXCEPTION(error::generic("Error writing PrivateKey") );
        }

        char* dat;
        uint32_t l = BIO_get_mem_data( mem, &dat );
        privkey.resize(l);
        memcpy( &privkey.front(), dat, l );

        BIO_free(mem);
        RSA_free(rsa);
        return true;
    }
}
