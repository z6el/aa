#pragma once

#include <unordered_map>

namespace pdb {
    class ComInitializer {
    public:
        ComInitializer( ) {
            HRESULT hr = CoInitialize( NULL );
            initialized = SUCCEEDED( hr );
        }
        ~ComInitializer( ) {
            if ( initialized )
                CoUninitialize( );
        }
    private:
        bool initialized;
    };

    static ComInitializer g_com_init;

    struct cv_info_t {
        GUID guid;
        DWORD age;
        std::string pdb_name;
        std::string guid_text;
        std::string age_text;
        std::string cache_name;
    };

    struct pdb_info {
        DWORD signature;
        GUID guid;
        DWORD age;
        char pdb_file_name[ 1 ];
    };

    class c_pdb {
    public:
        std::string m_module_bare;
        std::uint64_t m_module_base;
        std::vector<std::pair<std::string, std::uint64_t>> m_symbols;

        c_pdb( const char* module_name ) : m_module_name( module_name ) {
            std::string s = module_name;
            auto slash = s.find_last_of( "\\/" );
            m_module_bare = slash != std::string::npos ? s.substr( slash + 1 ) : s;
        }

        ~c_pdb( ) {
            cleanup( );
        }

        bool load( ) {
            if ( !setup_module_search_paths( ) ) {
                logging::print( oxorany( "failed to setup module search paths" ) );
                return false;
            }

            if ( !ensure_dia_available( ) ) {
                logging::print( oxorany( "msdia140.dll not found, place it next to bap-mapper.exe" ) );
                return false;
            }

            std::string kernel_path;
            m_module_base = get_kernel_module( m_module_bare.c_str( ), &kernel_path );
            if ( !m_module_base ) {
                logging::print( oxorany( "failed to find kernel module %s" ), m_module_bare.c_str( ) );
                return false;
            }

            m_pe_path = normalize_pe_path( kernel_path, m_module_bare );
            if ( m_pe_path.empty( ) )
                m_pe_path = get_default_pe_path( );

            cv_info_t cv_info{};
            if ( !read_cv_info( m_pe_path, cv_info ) ) {
                logging::print( oxorany( "failed to read PE debug info from %s" ), m_pe_path.c_str( ) );
                return false;
            }

            m_pdb_path = resolve_pdb_path( cv_info );
            if ( m_pdb_path.empty( ) ) {
                logging::print( oxorany( "failed to resolve PDB for %s" ), cv_info.pdb_name.c_str( ) );
                    return false;
            }

            if ( !open_pdb_session( m_pdb_path ) ) {
                logging::print( oxorany( "cached PDB invalid, deleting and re-downloading..." ) );
                DeleteFileA( m_pdb_path.c_str( ) );

                auto cache_dir = get_symbol_cache_dir( );
                m_pdb_path = download_pdb( cv_info, join_path( cache_dir, cv_info.cache_name ) );
                if ( m_pdb_path.empty( ) ) {
                    logging::print( oxorany( "failed to download PDB for %s" ), cv_info.pdb_name.c_str( ) );
                    return false;
                }

                if ( !open_pdb_session( m_pdb_path ) ) {
                    logging::print( oxorany( "failed to open PDB session" ) );
                DeleteFileA( m_pdb_path.c_str( ) );
                    return false;
                }
            }

            if ( !resolve_symbol_rva( oxorany( "NtGlobalFlag" ) ) && !resolve_symbol_rva( oxorany( "PsLoadedModuleList" ) ) ) {
                logging::print( oxorany( "PDB loaded but kernel symbols look invalid" ) );
                cleanup( );
                return false;
            }

            return true;
        }

        std::uint64_t get_symbol_address( const char* symbol_name ) {
            auto rva = resolve_symbol_rva( symbol_name );
            if ( !rva )
            return 0;
            return m_module_base + rva;
        }

        std::uint64_t find_member_in_udt( IDiaSymbol* pUDT, const std::wstring& member_name, LONG base_offset ) {
            CComPtr<IDiaEnumSymbols> pEnumData;
            if ( SUCCEEDED( pUDT->findChildren( SymTagData, member_name.c_str( ), nsfCaseInsensitive, &pEnumData ) ) && pEnumData ) {
                CComPtr<IDiaSymbol> pMember;
                ULONG celt = 0;
                if ( SUCCEEDED( pEnumData->Next( 1, &pMember, &celt ) ) && celt == 1 && pMember ) {
                    LONG offset = 0;
                    if ( SUCCEEDED( pMember->get_offset( &offset ) ) )
                        return static_cast< std::uint64_t >( base_offset + offset );
                }
            }

            CComPtr<IDiaEnumSymbols> pEnumBases;
            if ( FAILED( pUDT->findChildren( SymTagBaseClass, nullptr, nsNone, &pEnumBases ) ) || !pEnumBases )
                return 0;

            CComPtr<IDiaSymbol> pBase;
            ULONG celt = 0;
            while ( SUCCEEDED( pEnumBases->Next( 1, &pBase, &celt ) ) && celt == 1 ) {
                LONG base_off = 0;
                pBase->get_offset( &base_off );

                CComPtr<IDiaSymbol> pBaseType;
                if ( SUCCEEDED( pBase->get_type( &pBaseType ) ) && pBaseType ) {
                    auto result = find_member_in_udt( pBaseType, member_name, base_offset + base_off );
                    if ( result )
                        return result;
                }
                pBase.Release( );
            }

            return 0;
        }

        std::uint64_t get_struct_size( const char* type_name ) {
            if ( !m_pGlobal )
                return 0;

            std::wstring w_type( type_name, type_name + strlen( type_name ) );

            CComPtr<IDiaEnumSymbols> pEnumTypes;
            if ( FAILED( m_pGlobal->findChildren( SymTagUDT, w_type.c_str( ), nsfCaseInsensitive, &pEnumTypes ) ) || !pEnumTypes )
                return 0;

            CComPtr<IDiaSymbol> pUDT;
            ULONG celt = 0;
            if ( FAILED( pEnumTypes->Next( 1, &pUDT, &celt ) ) || celt != 1 || !pUDT )
                return 0;

            ULONGLONG size = 0;
            if ( FAILED( pUDT->get_length( &size ) ) )
                return 0;

            return static_cast< std::uint64_t >( size );
        }

        std::uint64_t get_struct_member( const char* type_name, const char* member_name ) {
            if ( !m_pGlobal )
                return 0;

            std::wstring w_type( type_name, type_name + strlen( type_name ) );
            std::wstring w_member( member_name, member_name + strlen( member_name ) );

            CComPtr<IDiaEnumSymbols> pEnumTypes;
            if ( FAILED( m_pGlobal->findChildren( SymTagUDT, w_type.c_str( ), nsfCaseInsensitive, &pEnumTypes ) ) || !pEnumTypes )
                return 0;

            CComPtr<IDiaSymbol> pUDT;
            ULONG celt = 0;
            if ( FAILED( pEnumTypes->Next( 1, &pUDT, &celt ) ) || celt != 1 || !pUDT )
                return 0;

            return find_member_in_udt( pUDT, w_member, 0 );
        }

        void dump_struct_members( const char* type_name ) {
            if ( !m_pGlobal )
                return;

            std::wstring w_type( type_name, type_name + strlen( type_name ) );

            CComPtr<IDiaEnumSymbols> pEnumTypes;
            if ( FAILED( m_pGlobal->findChildren( SymTagUDT, w_type.c_str( ), nsfCaseInsensitive, &pEnumTypes ) ) || !pEnumTypes )
                return;

            CComPtr<IDiaSymbol> pUDT;
            ULONG celt = 0;
            if ( FAILED( pEnumTypes->Next( 1, &pUDT, &celt ) ) || celt != 1 || !pUDT )
                return;

            CComPtr<IDiaEnumSymbols> pChildren;
            if ( FAILED( pUDT->findChildren( SymTagNull, nullptr, nsNone, &pChildren ) ) || !pChildren )
                return;

            CComPtr<IDiaSymbol> pChild;
            while ( SUCCEEDED( pChildren->Next( 1, &pChild, &celt ) ) && celt == 1 ) {
                BSTR name = nullptr;
                LONG offset = 0;
                pChild->get_name( &name );
                pChild->get_offset( &offset );
                if ( name ) {
                    char buf[ 256 ]{};
                    size_t n = 0;
                    wcstombs_s( &n, buf, name, sizeof( buf ) - 1 );
                    logging::print( oxorany( "  [0x%x] %s" ), offset, buf );
                    SysFreeString( name );
                }
                pChild.Release( );
            }
        }

        std::uint64_t get_symbol_rva( const char* symbol_name ) {
            return resolve_symbol_rva( symbol_name );
        }

        const std::string& get_pe_path( ) const {
            return m_pe_path;
        }

        static std::uint64_t get_kernel_module( const char* module_name, std::string* full_path = nullptr ) {
            void* buffer = nullptr;
            unsigned long buffer_size = 0;
            NTSTATUS status = NtQuerySystemInformation(
                static_cast< SYSTEM_INFORMATION_CLASS >( 11 ),
                buffer, buffer_size, &buffer_size
            );

            while ( status == 0xC0000004L ) {
                if ( buffer )
                    VirtualFree( buffer, 0, MEM_RELEASE );
                buffer = VirtualAlloc( nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE );
                if ( !buffer )
                    return 0;
                status = NtQuerySystemInformation(
                    static_cast< SYSTEM_INFORMATION_CLASS >( 11 ),
                    buffer, buffer_size, &buffer_size
                );
            }

            if ( !NT_SUCCESS( status ) || !buffer ) {
                if ( buffer )
                    VirtualFree( buffer, 0, MEM_RELEASE );
                return 0;
            }

            const auto modules = reinterpret_cast< rtl_process_modules_t* >( buffer );
            for ( auto idx = 0u; idx < modules->m_count; ++idx ) {
                const auto& module = modules->m_modules[ idx ];
                const auto current_module_name = std::string(
                    reinterpret_cast< const char* >( module.m_full_path ) + module.m_offset_to_file_name
                );

                if ( _stricmp( current_module_name.c_str( ), module_name ) ) {
                    continue;
                }

                const auto module_base = reinterpret_cast< std::uint64_t >( module.m_image_base );
                if ( full_path ) {
                    *full_path = normalize_pe_path(
                        reinterpret_cast< const char* >( module.m_full_path ),
                        current_module_name
                    );
                }

                VirtualFree( buffer, 0, MEM_RELEASE );
                return module_base;
            }

            VirtualFree( buffer, 0, MEM_RELEASE );
            return 0;
        }

    private:
        std::string m_module_name;
        std::string m_pe_path;
        std::string m_pdb_path;
        std::wstring m_dia_path;
        std::unordered_map<std::string, std::uint64_t> m_symbol_cache;

        IDiaDataSource* m_pSource = nullptr;
        IDiaSession* m_pSession = nullptr;
        IDiaSymbol* m_pGlobal = nullptr;

        bool setup_module_search_paths( ) {
            wchar_t exe_path[ MAX_PATH ] = { };
            if ( !GetModuleFileNameW( nullptr, exe_path, MAX_PATH ) )
                return false;

            for ( int i = static_cast< int >( wcslen( exe_path ) ) - 1; i >= 0; --i ) {
                if ( exe_path[ i ] == L'\\' || exe_path[ i ] == L'/' ) {
                    exe_path[ i ] = L'\0';
                    break;
                }
            }

            SetDllDirectoryW( exe_path );
            AddDllDirectory( exe_path );

            std::wstring dia_dir = std::wstring( exe_path ) + L"\\dia";
            CreateDirectoryW( dia_dir.c_str( ), nullptr );
            AddDllDirectory( dia_dir.c_str( ) );

            return true;
        }

        bool ensure_dia_available( ) {
            if ( m_dia_path.empty( ) )
                m_dia_path = locate_dia_module( );
            if ( m_dia_path.empty( ) )
                return false;

            if ( !GetModuleHandleW( m_dia_path.c_str( ) ) ) {
                if ( !LoadLibraryW( m_dia_path.c_str( ) ) )
                    return false;
            }

            return true;
        }

        std::wstring locate_dia_module( ) {
            wchar_t exe_path[ MAX_PATH ] = { };
            GetModuleFileNameW( nullptr, exe_path, MAX_PATH );
            wchar_t* slash = wcsrchr( exe_path, L'\\' );
            if ( slash )
                *slash = L'\0';

            const wchar_t* names[ ] = {
                L"msdia140.dll",
                L"msdia120.dll",
                L"msdia110.dll"
            };

            std::wstring dia_subdir = std::wstring( exe_path ) + L"\\dia";
            const wchar_t* dirs[ ] = { exe_path, dia_subdir.c_str( ) };

            for ( auto dir : dirs ) {
                for ( auto name : names ) {
                    std::wstring candidate = std::wstring( dir ) + L"\\" + name;
                    if ( GetFileAttributesW( candidate.c_str( ) ) != INVALID_FILE_ATTRIBUTES )
                        return candidate;
                }
            }

            wchar_t vs_dir[ MAX_PATH ] = { };
            DWORD vs_len = GetEnvironmentVariableW( L"VSINSTALLDIR", vs_dir, MAX_PATH );
            if ( vs_len > 0 ) {
                std::wstring candidate = std::wstring( vs_dir ) + L"DIA SDK\\bin\\amd64\\msdia140.dll";
                if ( GetFileAttributesW( candidate.c_str( ) ) != INVALID_FILE_ATTRIBUTES )
                    return candidate;
            }

            const wchar_t* known[ ] = {
                L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\DIA SDK\\bin\\amd64\\msdia140.dll",
                L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional\\DIA SDK\\bin\\amd64\\msdia140.dll",
                L"C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise\\DIA SDK\\bin\\amd64\\msdia140.dll",
                L"C:\\Program Files (x86)\\Microsoft Visual Studio\\2019\\Community\\DIA SDK\\bin\\amd64\\msdia140.dll"
            };

            for ( auto path : known ) {
                if ( GetFileAttributesW( path ) != INVALID_FILE_ATTRIBUTES )
                    return path;
            }

            return L"";
        }

        bool create_dia_source( CComPtr<IDiaDataSource>& source ) {
            HRESULT hr = CoCreateInstance( CLSID_DiaSource, nullptr, CLSCTX_INPROC_SERVER,
                IID_IDiaDataSource, reinterpret_cast< void** >( &source ) );
            if ( SUCCEEDED( hr ) )
                return true;

            const wchar_t* dll_names[ ] = { L"msdia140.dll", L"msdia120.dll", L"msdia110.dll" };
            for ( auto dll : dll_names ) {
                hr = NoRegCoCreate( dll, CLSID_DiaSource, IID_IDiaDataSource, reinterpret_cast< void** >( &source ) );
                if ( SUCCEEDED( hr ) )
                    return true;
            }

            logging::print( oxorany( "failed to create DIA data source: 0x%08x" ), hr );
            return false;
        }

        bool open_pdb_session( const std::string& pdb_path ) {
            CComPtr<IDiaDataSource> source;
            if ( !create_dia_source( source ) )
                return false;

            std::wstring wide_path( pdb_path.begin( ), pdb_path.end( ) );
            HRESULT hr = source->loadDataFromPdb( wide_path.c_str( ) );
            if ( FAILED( hr ) ) {
                logging::print( oxorany( "failed to load PDB %s: 0x%08x" ), pdb_path.c_str( ), hr );
                return false;
            }

            CComPtr<IDiaSession> session;
            hr = source->openSession( &session );
            if ( FAILED( hr ) ) {
                logging::print( oxorany( "failed to open DIA session: 0x%08x" ), hr );
                return false;
            }

            CComPtr<IDiaSymbol> global_scope;
            hr = session->get_globalScope( &global_scope );
            if ( FAILED( hr ) ) {
                logging::print( oxorany( "failed to get global scope: 0x%08x" ), hr );
                return false;
            }

            m_pSource = source.Detach( );
            m_pSession = session.Detach( );
            m_pGlobal = global_scope.Detach( );
            return true;
        }

        std::string get_default_pe_path( ) {
            return join_path( join_path( get_system_root( ), "System32" ), m_module_bare );
        }

        static std::string get_system_root( ) {
            char env_root[ MAX_PATH ] = { };
            if ( GetEnvironmentVariableA( "SystemRoot", env_root, MAX_PATH ) > 0 )
                return env_root;
            if ( GetEnvironmentVariableA( "SYSTEMROOT", env_root, MAX_PATH ) > 0 )
                return env_root;

            char windows_dir[ MAX_PATH ] = { };
            if ( GetWindowsDirectoryA( windows_dir, MAX_PATH ) > 0 )
                return windows_dir;

            return "C:\\Windows";
        }

        static std::string normalize_pe_path( const std::string& raw_path, const std::string& module_name ) {
            auto path_exists = []( const std::string& path ) {
                return !path.empty( ) && GetFileAttributesA( path.c_str( ) ) != INVALID_FILE_ATTRIBUTES;
            };

            auto to_lower = []( std::string value ) {
                for ( auto& ch : value )
                    ch = static_cast< char >( tolower( static_cast< unsigned char >( ch ) ) );
                return value;
            };

            const auto system_root = get_system_root( );

            std::vector<std::string> candidates;
            if ( !raw_path.empty( ) )
                candidates.push_back( raw_path );

            std::string lowered = to_lower( raw_path );
            if ( lowered.rfind( "\\systemroot\\", 0 ) == 0 ) {
                candidates.push_back( join_path( system_root, lowered.substr( 12 ) ) );
            }
            else if ( lowered.rfind( "systemroot\\", 0 ) == 0 ) {
                candidates.push_back( join_path( system_root, lowered.substr( 10 ) ) );
            }

            if ( lowered.rfind( "\\??\\", 0 ) == 0 ) {
                candidates.push_back( raw_path.substr( 4 ) );
            }

            candidates.push_back( join_path( join_path( system_root, "System32" ), module_name ) );
            candidates.push_back( join_path( join_path( system_root, "Sysnative" ), module_name ) );

            wchar_t system_dir[ MAX_PATH ] = { };
            if ( GetSystemDirectoryW( system_dir, MAX_PATH ) > 0 ) {
                candidates.push_back( join_path( narrow_path( system_dir ), module_name ) );
            }

            for ( const auto& candidate : candidates ) {
                if ( path_exists( candidate ) )
                    return candidate;
            }

            for ( const auto& candidate : candidates ) {
                std::string expanded( MAX_PATH, '\0' );
                DWORD expanded_len = ExpandEnvironmentStringsA( candidate.c_str( ), expanded.data( ), MAX_PATH );
                if ( expanded_len > 0 && expanded_len <= MAX_PATH ) {
                    expanded.resize( expanded_len - 1 );
                    if ( path_exists( expanded ) )
                        return expanded;
                }
            }

                return "";
        }

        std::string get_symbol_cache_dir( ) {
            wchar_t local_app_data[ MAX_PATH ] = { };
            if ( SHGetFolderPathW( nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, local_app_data ) == S_OK ) {
                std::wstring cache = std::wstring( local_app_data ) + L"\\bap\\symbols";
                CreateDirectoryW( ( std::wstring( local_app_data ) + L"\\bap" ).c_str( ), nullptr );
                CreateDirectoryW( cache.c_str( ), nullptr );
                return narrow_path( cache );
            }

            wchar_t exe_path[ MAX_PATH ] = { };
            GetModuleFileNameW( nullptr, exe_path, MAX_PATH );
            wchar_t* slash = wcsrchr( exe_path, L'\\' );
            if ( slash )
                *slash = L'\0';

            std::wstring cache = std::wstring( exe_path ) + L"\\symbols";
            CreateDirectoryW( cache.c_str( ), nullptr );
            return narrow_path( cache );
        }

        static std::string narrow_path( const std::wstring& value ) {
            if ( value.empty( ) )
                return "";
            int size = WideCharToMultiByte( CP_UTF8, 0, value.c_str( ), -1, nullptr, 0, nullptr, nullptr );
            if ( size <= 0 )
                return "";
            std::string out( size - 1, '\0' );
            WideCharToMultiByte( CP_UTF8, 0, value.c_str( ), -1, out.data( ), size, nullptr, nullptr );
            return out;
        }

        static std::wstring widen( const std::string& value ) {
            if ( value.empty( ) )
                return L"";
            int size = MultiByteToWideChar( CP_UTF8, 0, value.c_str( ), -1, nullptr, 0 );
            if ( size <= 0 )
                return L"";
            std::wstring out( size - 1, L'\0' );
            MultiByteToWideChar( CP_UTF8, 0, value.c_str( ), -1, out.data( ), size );
            return out;
        }

        static std::string join_path( const std::string& left, const std::string& right ) {
            if ( left.empty( ) )
                return right;
            if ( left.back( ) == '\\' )
                return left + right;
            return left + "\\" + right;
        }

        static bool is_valid_pdb_file( const std::string& path ) {
            WIN32_FILE_ATTRIBUTE_DATA attrs{ };
            if ( !GetFileAttributesExA( path.c_str( ), GetFileExInfoStandard, &attrs ) )
                return false;

            const auto file_size =
                ( static_cast< std::uint64_t >( attrs.nFileSizeHigh ) << 32 ) | attrs.nFileSizeLow;
            if ( file_size < 1024 * 1024 )
                return false;

            std::ifstream file( path, std::ios::binary );
            if ( !file.is_open( ) )
                return false;

            char magic[ 32 ] = { };
            file.read( magic, sizeof( magic ) - 1 );
            if ( !file )
                return false;

            return std::string( magic ).rfind( "Microsoft C/C++", 0 ) == 0;
        }

        static bool read_file_bytes( const std::string& path, std::vector<char>& buffer ) {
            std::ifstream file( path, std::ios::binary | std::ios::ate );
            if ( !file.is_open( ) )
                return false;

            auto size = file.tellg( );
            if ( size <= 0 )
                return false;

            buffer.resize( static_cast< size_t >( size ) );
            file.seekg( 0, std::ios::beg );
            return static_cast< bool >( file.read( buffer.data( ), size ) );
        }

        static bool build_mapped_image( const std::vector<char>& file_data, std::unique_ptr<BYTE[]>& image_buffer, IMAGE_NT_HEADERS** nt_headers ) {
            if ( file_data.size( ) < sizeof( IMAGE_DOS_HEADER ) )
                return false;

            auto dos = reinterpret_cast< const IMAGE_DOS_HEADER* >( file_data.data( ) );
            if ( dos->e_magic != IMAGE_DOS_SIGNATURE )
                return false;

            if ( file_data.size( ) < static_cast< size_t >( dos->e_lfanew ) + sizeof( IMAGE_NT_HEADERS ) )
                return false;

            auto nt = reinterpret_cast< const IMAGE_NT_HEADERS* >( file_data.data( ) + dos->e_lfanew );
            if ( nt->Signature != IMAGE_NT_SIGNATURE )
                return false;

            bool is_x86 = nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386;
            auto opt32 = reinterpret_cast< const IMAGE_OPTIONAL_HEADER32* >( &nt->OptionalHeader );
            auto opt64 = reinterpret_cast< const IMAGE_OPTIONAL_HEADER64* >( &nt->OptionalHeader );
            auto image_size = is_x86 ? opt32->SizeOfImage : opt64->SizeOfImage;
            auto headers_size = is_x86 ? opt32->SizeOfHeaders : opt64->SizeOfHeaders;

            image_buffer = std::make_unique<BYTE[]>( image_size );
            if ( !image_buffer )
                return false;

            std::memcpy( image_buffer.get( ), file_data.data( ), headers_size );

            auto section = IMAGE_FIRST_SECTION( const_cast< IMAGE_NT_HEADERS* >( nt ) );
            for ( UINT i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section ) {
                if ( !section->SizeOfRawData )
                    continue;
                if ( section->PointerToRawData + section->SizeOfRawData > file_data.size( ) )
                    return false;
                std::memcpy(
                    image_buffer.get( ) + section->VirtualAddress,
                    file_data.data( ) + section->PointerToRawData,
                    section->SizeOfRawData
                );
            }

            *nt_headers = reinterpret_cast< IMAGE_NT_HEADERS* >( image_buffer.get( ) + dos->e_lfanew );
            return true;
        }

        static bool format_cv_info( const pdb_info* info, size_t name_space, cv_info_t& out ) {
            if ( !info || info->signature != 0x53445352 )
                return false;

            std::string pdb_name;
            pdb_name.reserve( 64 );
            for ( size_t i = 0; i < name_space && info->pdb_file_name[ i ]; ++i ) {
                const auto ch = static_cast< unsigned char >( info->pdb_file_name[ i ] );
                if ( ch < 0x20 )
                    break;
                pdb_name.push_back( static_cast< char >( ch ) );
            }

            if ( pdb_name.size( ) < 5 || pdb_name.find( ".pdb" ) == std::string::npos )
                return false;

            wchar_t guid_wide[ 64 ] = { };
            if ( !StringFromGUID2( info->guid, guid_wide, 64 ) )
                return false;

            char guid_ascii[ 64 ] = { };
            size_t guid_len = 0;
            wcstombs_s( &guid_len, guid_ascii, guid_wide, sizeof( guid_ascii ) );

            std::string guid_text;
            guid_text.reserve( 32 );
            for ( size_t i = 0; i < guid_len; ++i ) {
                char c = guid_ascii[ i ];
                if ( ( c >= '0' && c <= '9' ) || ( c >= 'A' && c <= 'F' ) || ( c >= 'a' && c <= 'f' ) )
                    guid_text.push_back( static_cast< char >( toupper( static_cast< unsigned char >( c ) ) ) );
            }

            if ( guid_text.size( ) < 32 )
                return false;

            char age_text[ 16 ] = { };
            sprintf_s( age_text, "%X", info->age );

            out.guid = info->guid;
            out.age = info->age;
            out.pdb_name = std::move( pdb_name );
            out.guid_text = std::move( guid_text );
            out.age_text = age_text;
            out.cache_name = out.pdb_name + "_" + out.guid_text + out.age_text + ".pdb";
            return true;
        }

        static bool find_cv_info_in_buffer( const char* data, size_t size, cv_info_t& out ) {
            if ( !data || size < sizeof( pdb_info ) )
                return false;

            for ( size_t offset = 0; offset + sizeof( pdb_info ) <= size; ++offset ) {
                const auto info = reinterpret_cast< const pdb_info* >( data + offset );
                if ( info->signature != 0x53445352 )
                    continue;

                if ( format_cv_info( info, size - offset - offsetof( pdb_info, pdb_file_name ), out ) )
                    return true;
            }

            return false;
        }

        static bool read_cv_info_from_debug_directory(
            const std::vector<char>& file_data,
            IMAGE_NT_HEADERS* nt,
            BYTE* image_buffer,
            cv_info_t& out
        ) {
            bool is_x86 = nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386;
            auto opt32 = reinterpret_cast< IMAGE_OPTIONAL_HEADER32* >( &nt->OptionalHeader );
            auto opt64 = reinterpret_cast< IMAGE_OPTIONAL_HEADER64* >( &nt->OptionalHeader );
            auto image_size = is_x86 ? opt32->SizeOfImage : opt64->SizeOfImage;
            auto data_dir = is_x86
                ? &opt32->DataDirectory[ IMAGE_DIRECTORY_ENTRY_DEBUG ]
                : &opt64->DataDirectory[ IMAGE_DIRECTORY_ENTRY_DEBUG ];

            if ( !data_dir->VirtualAddress || !data_dir->Size )
                return false;

            auto debug_dir = reinterpret_cast< IMAGE_DEBUG_DIRECTORY* >( image_buffer + data_dir->VirtualAddress );
            auto debug_count = data_dir->Size / sizeof( IMAGE_DEBUG_DIRECTORY );

            for ( DWORD i = 0; i < debug_count; ++i ) {
                if ( debug_dir[ i ].Type != IMAGE_DEBUG_TYPE_CODEVIEW )
                    continue;

                if ( debug_dir[ i ].PointerToRawData ) {
                    const auto offset = debug_dir[ i ].PointerToRawData;
                    if ( offset + sizeof( pdb_info ) <= file_data.size( ) ) {
                        const auto info = reinterpret_cast< const pdb_info* >( file_data.data( ) + offset );
                        if ( format_cv_info( info, file_data.size( ) - offset - offsetof( pdb_info, pdb_file_name ), out ) )
                            return true;
                    }
                }

                const auto offset = debug_dir[ i ].AddressOfRawData;
                if ( offset + sizeof( pdb_info ) > image_size )
                    continue;

                const auto info = reinterpret_cast< const pdb_info* >( image_buffer + offset );
                if ( format_cv_info( info, image_size - offset - offsetof( pdb_info, pdb_file_name ), out ) )
                    return true;
            }

            return false;
        }

        static bool read_cv_info_from_pe_index( IMAGE_NT_HEADERS* nt, const std::string& module_name, cv_info_t& out ) {
            bool is_x86 = nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386;
            auto opt32 = reinterpret_cast< IMAGE_OPTIONAL_HEADER32* >( &nt->OptionalHeader );
            auto opt64 = reinterpret_cast< IMAGE_OPTIONAL_HEADER64* >( &nt->OptionalHeader );
            const auto image_size = is_x86 ? opt32->SizeOfImage : opt64->SizeOfImage;

            char index[ 32 ] = { };
            sprintf_s( index, "%08X%08X", nt->FileHeader.TimeDateStamp, image_size );

            std::string pdb_name = module_name;
            auto dot = pdb_name.rfind( '.' );
            if ( dot != std::string::npos )
                pdb_name = pdb_name.substr( 0, dot );
            pdb_name += ".pdb";

            if ( _stricmp( module_name.c_str( ), "ntoskrnl.exe" ) == 0 )
                pdb_name = "ntkrnlmp.pdb";

            out.pdb_name = std::move( pdb_name );
            out.guid_text = index;
            out.age_text = "";
            out.cache_name = out.pdb_name + "_" + out.guid_text + ".pdb";
            return true;
        }

        bool read_cv_info( const std::string& pe_path, cv_info_t& out ) {
            std::vector<char> file_data;
            if ( !read_file_bytes( pe_path, file_data ) ) {
                logging::print( oxorany( "failed to open PE file: %s" ), pe_path.c_str( ) );
                return false;
            }

            if ( find_cv_info_in_buffer( file_data.data( ), file_data.size( ), out ) )
                return true;

            std::unique_ptr<BYTE[]> image_buffer;
            IMAGE_NT_HEADERS* nt = nullptr;
            if ( !build_mapped_image( file_data, image_buffer, &nt ) )
                return false;

            const bool is_x86 = nt->FileHeader.Machine == IMAGE_FILE_MACHINE_I386;

            if ( read_cv_info_from_debug_directory( file_data, nt, image_buffer.get( ), out ) )
                return true;

            if ( find_cv_info_in_buffer( reinterpret_cast< const char* >( image_buffer.get( ) ),
                is_x86
                    ? reinterpret_cast< IMAGE_OPTIONAL_HEADER32* >( &nt->OptionalHeader )->SizeOfImage
                    : reinterpret_cast< IMAGE_OPTIONAL_HEADER64* >( &nt->OptionalHeader )->SizeOfImage,
                out ) )
                return true;

            if ( read_cv_info_from_pe_index( nt, m_module_bare, out ) )
                return true;

            return false;
        }

        std::string resolve_pdb_path( const cv_info_t& cv_info ) {
            auto cache_dir = get_symbol_cache_dir( );
            auto cached_path = join_path( cache_dir, cv_info.cache_name );

            if ( is_valid_pdb_file( cached_path ) )
                return cached_path;

            if ( GetFileAttributesA( cached_path.c_str( ) ) != INVALID_FILE_ATTRIBUTES )
                DeleteFileA( cached_path.c_str( ) );

            for ( const auto& entry : std::vector<std::string>{
                join_path( cache_dir, cv_info.pdb_name ),
                join_path( cache_dir, cv_info.pdb_name + "_" + cv_info.guid_text + ".pdb" ),
            } ) {
                if ( GetFileAttributesA( entry.c_str( ) ) != INVALID_FILE_ATTRIBUTES )
                    DeleteFileA( entry.c_str( ) );
            }

            wchar_t cwd[ MAX_PATH ] = { };
            if ( GetCurrentDirectoryW( MAX_PATH, cwd ) ) {
                auto local_path = narrow_path( std::wstring( cwd ) + L"\\" + widen( cv_info.cache_name ) );
                if ( is_valid_pdb_file( local_path ) ) {
                    CopyFileA( local_path.c_str( ), cached_path.c_str( ), FALSE );
                    if ( is_valid_pdb_file( cached_path ) )
                        return cached_path;
                }

                std::string prefix = get_module_prefix( );
                WIN32_FIND_DATAA fd{};
                auto pattern = join_path( narrow_path( cwd ), prefix + "_*.pdb" );
                HANDLE find = FindFirstFileA( pattern.c_str( ), &fd );
                if ( find != INVALID_HANDLE_VALUE ) {
                    auto legacy = join_path( narrow_path( cwd ), fd.cFileName );
                    FindClose( find );
                    if ( is_valid_pdb_file( legacy ) ) {
                        CopyFileA( legacy.c_str( ), cached_path.c_str( ), FALSE );
                        if ( is_valid_pdb_file( cached_path ) )
                            return cached_path;
                    }
                }
            }

            return download_pdb( cv_info, cached_path );
        }

        std::string download_pdb( const cv_info_t& cv_info, const std::string& output_path ) {
            const char* servers[ ] = {
                "https://msdl.microsoft.com/download/symbols/",
                "https://symbols.mozilla.org/nt6/",
                "https://chromium-browser-symsrv.commondatastorage.googleapis.com/"
            };

            for ( auto server : servers ) {
                std::string url = server;
                url += cv_info.pdb_name;
                url += "/";
                url += cv_info.guid_text;
                if ( !cv_info.age_text.empty( ) )
                    url += cv_info.age_text;
                url += "/";
                url += cv_info.pdb_name;

                logging::print( oxorany( "downloading %s from symbol server..." ), cv_info.pdb_name.c_str( ) );

                if ( GetFileAttributesA( output_path.c_str( ) ) != INVALID_FILE_ATTRIBUTES )
                    DeleteFileA( output_path.c_str( ) );

                HRESULT hr = URLDownloadToFileA( nullptr, url.c_str( ), output_path.c_str( ), 0, nullptr );
                if ( FAILED( hr ) ) {
                    logging::print( oxorany( "symbol download failed: 0x%08x" ), hr );
                    continue;
                }

                if ( is_valid_pdb_file( output_path ) )
                    return output_path;

                DeleteFileA( output_path.c_str( ) );
            }

            return "";
        }

        std::string get_module_prefix( ) {
            std::string prefix = m_module_bare;
            auto dot = prefix.rfind( '.' );
            if ( dot != std::string::npos )
                prefix = prefix.substr( 0, dot );
            for ( auto& c : prefix )
                c = static_cast< char >( tolower( static_cast< unsigned char >( c ) ) );
            return prefix;
        }

        std::uint64_t resolve_symbol_rva( const char* symbol_name ) {
            if ( !symbol_name || !symbol_name[ 0 ] )
                return 0;

            std::string key = symbol_name;
            auto cached = m_symbol_cache.find( key );
            if ( cached != m_symbol_cache.end( ) )
                return cached->second;

            std::wstring wide_name( symbol_name, symbol_name + strlen( symbol_name ) );
            if ( auto rva = lookup_symbol_tag( wide_name, key, SymTagPublicSymbol ) )
                return rva;
            if ( auto rva = lookup_symbol_tag( wide_name, key, SymTagFunction ) )
                return rva;
            if ( auto rva = lookup_symbol_tag( wide_name, key, SymTagData ) )
                return rva;

            m_symbol_cache.emplace( key, 0 );
            return 0;
        }

        std::uint64_t lookup_symbol_tag( const std::wstring& wide_name, const std::string& key, enum SymTagEnum sym_tag ) {
            CComPtr<IDiaEnumSymbols> enum_symbols;
            if ( FAILED( m_pGlobal->findChildren( sym_tag, wide_name.c_str( ), nsfCaseInsensitive, &enum_symbols ) ) || !enum_symbols )
                return 0;

            CComPtr<IDiaSymbol> symbol;
            ULONG count = 0;
            while ( SUCCEEDED( enum_symbols->Next( 1, &symbol, &count ) ) && count == 1 ) {
                DWORD rva = 0;
                if ( SUCCEEDED( symbol->get_relativeVirtualAddress( &rva ) ) && rva ) {
                    m_symbol_cache.emplace( key, rva );
                    m_symbols.emplace_back( key, rva );
                    return rva;
                }
                symbol.Release( );
            }

            return 0;
        }

        void cleanup( ) {
            if ( m_pGlobal ) {
                m_pGlobal->Release( );
                m_pGlobal = nullptr;
            }
            if ( m_pSession ) {
                m_pSession->Release( );
                m_pSession = nullptr;
            }
            if ( m_pSource ) {
                m_pSource->Release( );
                m_pSource = nullptr;
            }
        }
    };
}
