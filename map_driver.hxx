#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

// NOTE: This header must only be included by exactly one .cxx file
// (currently main.cxx) because impl/includes.h defines several
// non-inline free functions and globals inside its included headers.
// Including it from multiple TUs produces LNK2005 duplicates.

inline bool bap_map_driver_image( const std::uint8_t* image, std::size_t size ) {
    if ( !image || !size || size > ( 32u * 1024u * 1024u ) )
        return false;

    if ( !utility::adjust_privilege( 20 ) )
        return false;

    std::vector<std::uint8_t> driver_image( image, image + size );
    auto dependency = std::make_shared<map::c_dependency>( driver_image );

    logging::print( oxorany( "loading ntoskrnl PDB..." ) );
    if ( !g_pdb->load( ) ) {
        logging::print( oxorany( "could not load PDB" ) );
        return false;
    }

    logging::print( oxorany( "loaded PDB for %s\n" ), g_pdb->m_module_bare.c_str( ) );

    if ( !g_service->create( ) ) {
        logging::print( oxorany( "Could not setup service" ) );
        g_service->unload( );
        return false;
    }

    if ( !g_driver->initialize( ) ) {
        logging::print( oxorany( "Could not setup driver" ) );
        g_service->unload( );
        return false;
    }

    if ( !g_paging->setup( ) ) {
        logging::print( oxorany( "could not get directory table base" ) );
        g_service->unload( );
        g_driver->unload( );
        return false;
    }

    if ( !g_syscall->setup( ) ) {
        logging::print( oxorany( "could not setup kernel execution" ) );
        g_service->unload( );
        g_driver->unload( );
        return false;
    }

    if ( !dependency->load( ) ) {
        logging::print( oxorany( "Could not load dependency" ) );
        g_service->unload( );
        g_driver->unload( );
        return false;
    }

    auto mapper = std::make_unique<map::c_map>( dependency );
    if ( !mapper->create( ) ) {
        logging::print( oxorany( "could not manual map" ) );
        g_service->unload( );
        g_driver->unload( );
        return false;
    }

    if ( !mapper->execute( ) ) {
        logging::print( oxorany( "could not execute." ) );
        g_service->unload( );
        g_driver->unload( );
        return false;
    }

    g_service->unload( );
    g_driver->unload( );
    return true;
}

inline bool bap_map_driver_image( const std::vector<std::uint8_t>& image ) {
    return bap_map_driver_image( image.data( ), image.size( ) );
}
