#ifndef _SCRYPT_SHA1_HPP_
#define _SCRYPT_SHA1_HPP_
#include <string>
#include <string.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <openssl/sha.h>
#include <stdint.h>
#include <boost/static_assert.hpp>
#include <boost/type_traits/is_fundamental.hpp>

namespace scrypt { 

inline uint8_t from_hex( char c ) {
  if( c >= '0' && c <= '9' )
    return c - '0';
  if( c >= 'a' && c <= 'f' )
      return c - 'a' + 10;
  if( c >= 'A' && c <= 'F' )
      return c - 'A' + 10;
  return 0;
}

struct sha1 {
    uint32_t hash[5];

    explicit sha1( const std::string& hex_str ) {
        uint8_t* c = (uint8_t*)hash;
        for( uint32_t i = 0; i < sizeof(hash); ++i )
          c[i] = (from_hex(hex_str[i*2])<<4) | from_hex(hex_str[i*2+1]);
    }
    sha1( ) { memset(hash, 0, sizeof(hash) ); }
    sha1( const sha1& c ) { memcpy(hash, c.hash, sizeof(hash) );    }
    sha1& operator = ( const sha1& b ) {
        memcpy( hash, b.hash, sizeof(hash) );
        return *this;
    }
    inline std::string str()const;
    operator std::string()const { return  str(); }

    template<typename T>
    inline friend T& operator<<( T& ds, const scrypt::sha1& ep ) {
        ds.write( (const char*)ep.hash, sizeof(ep.hash) );
        return ds;
    }
    template<typename T>
    inline friend T& operator>>( T& ds, scrypt::sha1& ep ) {
        ds.read( (char*)ep.hash, sizeof(ep.hash) );
        return ds;
    }
};
inline std::ostream& operator<< ( std::ostream& os, const sha1& h ) {
    const char* to_hex="0123456789abcdef";
    uint8_t* c = (uint8_t*)h.hash;
    for( uint32_t i = 0; i < sizeof(h.hash); ++i )
        os << to_hex[(c[i]>>4)] << to_hex[(c[i] &0x0f)];
    return os;
}

inline std::istream& operator>>(std::istream& is, sha1& h ) {
    uint8_t* c = (uint8_t*)h.hash;
    for( uint32_t i = 0; i < sizeof(h.hash); ++i ) {
      char h, l;
      h = is.get(); l = is.get();
      c[i] =  from_hex(h)<<4 | from_hex(l);
    }
    return is;
} 

inline sha1 operator << ( const sha1& h1, uint32_t i )
{
    sha1 result;
    uint8_t* r = (uint8_t*)result.hash;
    uint8_t* s = (uint8_t*)h1.hash;
    for( uint32_t p = 0; p < sizeof(h1.hash)-1; ++p )
        r[p] = s[p] << i | (s[p+1]>>(8-i));
    r[19] = s[19] << i;
    return result;
}
inline sha1 operator ^ ( const sha1& h1, const sha1 h2 )
{
    sha1 result;
    result.hash[0] = h1.hash[0] ^ h2.hash[0];
    result.hash[1] = h1.hash[1] ^ h2.hash[1];
    result.hash[2] = h1.hash[2] ^ h2.hash[2];
    result.hash[3] = h1.hash[3] ^ h2.hash[3];
    result.hash[4] = h1.hash[4] ^ h2.hash[4];
    return result;
}
inline bool operator >= ( const sha1& h1, const sha1 h2 ) {
    return memcmp( h1.hash, h2.hash, sizeof(h1.hash) ) >= 0;
}
inline bool operator > ( const sha1& h1, const sha1 h2 ) {
    return memcmp( h1.hash, h2.hash, sizeof(h1.hash) ) > 0;
}



inline bool operator == ( const sha1& a, const sha1& b ) {
   return memcmp( a.hash, b.hash, sizeof(a.hash) ) == 0; 
}
inline bool operator != ( const sha1& a, const sha1& b ) {
   return memcmp( a.hash, b.hash, sizeof(a.hash) ) != 0; 
}
inline bool operator < ( const sha1& a, const sha1& b ) {
   return memcmp( a.hash, b.hash, sizeof(a.hash) ) < 0; 
}
inline std::string sha1::str()const {
    std::stringstream ss; 
    const char* to_hex="0123456789abcdef";
    uint8_t* c = (uint8_t*)hash;
    for( uint32_t i = 0; i < sizeof(hash); ++i )
        ss << to_hex[(c[i]>>4)] << to_hex[(c[i] &0x0f)];
    return ss.str();
}

class sha1_encoder {
    public:
        sha1_encoder() { reset(); }
        ~sha1_encoder(){};

        /*
         *  Re-initialize the class
         */
        void reset(){ SHA1_Init(&ctx); }

       template<typename DATA>
       inline sha1_encoder& operator<<(const DATA& d) {
         BOOST_STATIC_ASSERT( boost::is_fundamental<DATA>::value );
         write( (const char*)&d, sizeof(d) );
         return *this;
       }

        /*
         *  Returns the message digest
         */
        bool result(unsigned char*message_digest_array) {
            SHA1_Final(message_digest_array, &ctx );
        }
        sha1 result() {
            sha1 h;
            SHA1_Final((unsigned char*)h.hash, &ctx );
            return h;
        }

        /*
         *  Provide input to sha1
         */
        void write( const unsigned char *message_array,
                    unsigned            length){ SHA1_Update( &ctx, message_array, length ); }
        void write( const char  *message_array,
                    unsigned    length){ SHA1_Update( &ctx, message_array, length ); }

        void put( char d ) { write(&d, 1 ); }
        static sha1 hash( const std::string& str ) {
            sha1_encoder sh;
            sh.write( str.c_str(), str.size() );
            sha1 hc;
            sh.result( (unsigned char*)hc.hash );
            return hc;
        }
        static sha1 hash( const std::vector<char>& str ) {
            sha1_encoder sh;
            sh.write( &str.front(), str.size() );
            sha1 hc;
            sh.result( (unsigned char*)hc.hash );
            return hc;
        }

    private:
        SHA_CTX ctx;
};

inline void sha1_hash( scrypt::sha1& hc, const char* d, uint32_t s ) {
    sha1_encoder enc; 
    enc.write( d, s );
    enc.result((unsigned char*)hc.hash);
}

} // namespace scrypt


#endif
