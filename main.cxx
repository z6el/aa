#include <impl/includes.h>
#include "map_driver.hxx"

static int finish( int code, bool auto_mode ) {
	if ( auto_mode )
		return code;
	std::getchar( );
	return code;
}

static bool load_driver_from_shm( const char* name, std::vector<std::uint8_t>& out ) {
	if ( !name || !name[ 0 ] )
		return false;

	const auto mapping = OpenFileMappingA( FILE_MAP_READ, FALSE, name );
	if ( !mapping )
		return false;

	const auto view = MapViewOfFile( mapping, FILE_MAP_READ, 0, 0, 0 );
	if ( !view ) {
		CloseHandle( mapping );
		return false;
	}

	MEMORY_BASIC_INFORMATION mbi{};
	if ( !VirtualQuery( view, &mbi, sizeof( mbi ) ) || mbi.RegionSize < sizeof( std::uint32_t ) ) {
		UnmapViewOfFile( view );
		CloseHandle( mapping );
		return false;
	}

	const auto size = *reinterpret_cast< const std::uint32_t* >( view );
	if ( !size || size > mbi.RegionSize - sizeof( std::uint32_t ) || size > ( 32u * 1024u * 1024u ) ) {
		UnmapViewOfFile( view );
		CloseHandle( mapping );
		return false;
	}

	const auto bytes = reinterpret_cast< const std::uint8_t* >( view ) + sizeof( std::uint32_t );
	out.assign( bytes, bytes + size );

	UnmapViewOfFile( view );
	CloseHandle( mapping );
	return !out.empty( );
}

static bool load_driver_from_file( const char* path, std::vector<std::uint8_t>& out ) {
	if ( !path || !path[ 0 ] )
		return false;

	std::ifstream file( path, std::ios::binary | std::ios::ate );
	if ( !file )
		return false;

	const auto size = static_cast<std::size_t>( file.tellg( ) );
	if ( !size || size > ( 32u * 1024u * 1024u ) )
		return false;

	out.resize( size );
	file.seekg( 0, std::ios::beg );
	if ( !file.read( reinterpret_cast<char*>( out.data( ) ), static_cast<std::streamsize>( size ) ) )
		return false;

	return true;
}

int main( int argc, char** argv ) {
	bool auto_mode = false;
	const char* driver_path = nullptr;
	const char* shm_name = nullptr;

	for ( int i = 1; i < argc; ++i ) {
		if ( !strcmp( argv[ i ], "--auto" ) || !strcmp( argv[ i ], "-auto" ) ) {
			auto_mode = true;
			continue;
		}
		if ( !strcmp( argv[ i ], "--shm" ) || !strcmp( argv[ i ], "-shm" ) ) {
			if ( i + 1 < argc )
				shm_name = argv[ ++i ];
			continue;
		}
		if ( !driver_path )
			driver_path = argv[ i ];
	}

	if ( !auto_mode ) {
		SetConsoleTitleA( oxorany( "bap-mapper" ) );
		SetUnhandledExceptionFilter( handler::crash_handler );

		auto std_handle = GetStdHandle( STD_OUTPUT_HANDLE );
		DWORD mode;
		GetConsoleMode( std_handle, &mode );
		mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
		SetConsoleMode( std_handle, mode );

		CONSOLE_FONT_INFOEX cfi{ };
		cfi.cbSize = sizeof( cfi );
		cfi.nFont = 0;
		cfi.dwFontSize.X = 8;
		cfi.dwFontSize.Y = 15;
		cfi.FontFamily = FF_DONTCARE;
		cfi.FontWeight = FW_NORMAL;
		wcscpy_s( cfi.FaceName, oxorany( L"Raster Fonts" ) );
		SetCurrentConsoleFontEx( GetStdHandle( STD_OUTPUT_HANDLE ), FALSE, &cfi );
	}

	std::vector<std::uint8_t> driver_image;
	if ( shm_name ) {
		if ( !load_driver_from_shm( shm_name, driver_image ) ) {
			logging::print( oxorany( "Could not load driver from shared memory" ) );
			return finish( 1, auto_mode );
		}
	}
	else if ( driver_path ) {
		if ( !load_driver_from_file( driver_path, driver_image ) ) {
			logging::print( oxorany( "Could not load driver file" ) );
			return finish( 1, auto_mode );
		}
	}
	else {
		logging::print( oxorany( "Missing parameters" ) );
		return finish( 1, auto_mode );
	}

	if ( !bap_map_driver_image( driver_image ) )
		return finish( 1, auto_mode );

	return finish( 0, auto_mode );
}
