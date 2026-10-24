#pragma once
#include <cstdio>
#include <cstdarg>
#include <fcntl.h>
#include <io.h>
#include <mutex>

namespace logging {
    inline std::FILE* log_file( ) {
        static std::FILE* file = nullptr;
        static std::once_flag once;
        std::call_once( once, [ ] {
            wchar_t path[ MAX_PATH ] = { };
            GetModuleFileNameW( nullptr, path, MAX_PATH );
            wchar_t* slash = wcsrchr( path, L'\\' );
            if ( slash )
                *slash = L'\0';
            wcscat_s( path, L"\\log.txt" );

            auto handle = CreateFileW(
                path,
                GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                nullptr,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                nullptr
            );

            if ( handle == INVALID_HANDLE_VALUE )
                return;

            auto fd = _open_osfhandle( reinterpret_cast< intptr_t >( handle ), _O_WRONLY );
            if ( fd == -1 ) {
                CloseHandle( handle );
                return;
            }

            file = _wfdopen( fd, L"w" );
            if ( !file )
                _close( fd );
        } );
        return file;
    }

    template<typename... Args>
    inline void print( const char* format, Args... args ) {
        auto now = std::chrono::system_clock::now( );
        std::time_t time = std::chrono::system_clock::to_time_t( now );
        tm local_tm;
        localtime_s( &local_tm, &time );

        char line[ 2048 ] = { };
        int prefix_len = sprintf_s( line, sizeof( line ),
            "[%02d/%02d/%04d %02d:%02d:%02d] [bap] ",
            local_tm.tm_mon + 1,
            local_tm.tm_mday,
            local_tm.tm_year + 1900,
            local_tm.tm_hour,
            local_tm.tm_min,
            local_tm.tm_sec );

        if ( prefix_len > 0 )
            sprintf_s( line + prefix_len, sizeof( line ) - prefix_len, format, args... );

        printf( oxorany( "\x1b[38;2;138;45;198m[\x1b[38;2;148;58;208m%02d\x1b[38;2;158;72;216m/\x1b[38;2;168;86;224m%02d\x1b[38;2;178;100;232m/\x1b[38;2;188;114;238m%04d\x1b[38;2;192;124;242m \x1b[38;2;196;134;246m%02d\x1b[38;2;180;110;240m:\x1b[38;2;170;125;248m%02d\x1b[38;2;170;125;248m:\x1b[38;2;170;125;248m%02d]\x1b[0m " ),
            local_tm.tm_mon + 1,
            local_tm.tm_mday,
            local_tm.tm_year + 1900,
            local_tm.tm_hour,
            local_tm.tm_min,
            local_tm.tm_sec );
        printf( oxorany( "\x1b[38;2;160;80;220m[bap]\x1b[0m " ) );
        printf( oxorany( "\x1b[37m" ) );
        printf( format, args... );
        printf( oxorany( "\x1b[0m\n" ) );

        if ( auto file = log_file( ) ) {
            fputs( line, file );
            fputc( '\n', file );
            fflush( file );
        }
    }
}
