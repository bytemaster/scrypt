#ifndef _SCRYPT_ERROR_HPP_
#define _SCRYPT_ERROR_HPP_
#include <boost/exception/all.hpp>

namespace scrypt {
namespace error {
    struct scrypt_exception : public std::exception, public virtual boost::exception {
        const char*  what()const throw() { return "scrypt exception";     }
        virtual void rethrow()const      { BOOST_THROW_EXCEPTION(*this);  }
    };
    struct invalid_buffer_length : public virtual scrypt_exception {
        const char*  what()const throw() { return "Invalid buffer length"; }
        virtual void rethrow()const      { BOOST_THROW_EXCEPTION(*this);   }
    };
    struct invalid_key_length : public virtual scrypt_exception {
        const char*  what()const throw() { return "Invalid key length";    }
        virtual void rethrow()const      { BOOST_THROW_EXCEPTION(*this);   }
    };
    struct generic : public virtual scrypt_exception {
        generic( const std::string& msg = "" ):m_msg(msg){}
        ~generic()throw() {}
        const char*  what()const throw() { return m_msg.c_str(); }
        virtual void rethrow()const      { BOOST_THROW_EXCEPTION( *this ); }

        private:
            std::string m_msg;
    };
} } // namesapce scrypt::error

#endif
