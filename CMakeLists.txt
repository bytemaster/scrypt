SET( headers 
    crypto.hpp
    blowfish.hpp
    dh.hpp
    )
     
SET( sources
    blowfish.cpp
    scrypt.cpp
    dh.cpp
   )

SET( libraries 
     crypto
     ${Boost_SYSTEM_LIBRARY} 
     ${Boost_THREAD_LIBRARY} 
   )

include_directories( include )
INCLUDE_DIRECTORIES( ${Boost_INCLUDE_DIR} )
include_directories( /usr/include )

INCLUDE( SetupTargetMacros )

SETUP_LIBRARY( scrypt  SOURCES   ${sources}
                       LIBRARIES ${libraries} 
                       AUTO_INSTALL_HEADERS 
                       LIBRARY_TYPE ${LIBRARY_BUILD_TYPE} )
install( DIRECTORY include/scrypt DESTINATION include )
