#pragma once
#include <atomic>
#include <fstream>
#include <thread>
#include <vector>

namespace paging {
    constexpr auto page_4kb_size = 0x1000ull;
    constexpr auto page_2mb_size = 0x200000ull;
    constexpr auto page_1gb_size = 0x40000000ull;

    constexpr auto page_shift = 12ull;
    constexpr auto page_2mb_shift = 21ull;
    constexpr auto page_1gb_shift = 30ull;

    constexpr auto page_4kb_mask = 0xFFFull;
    constexpr auto page_2mb_mask = 0x1FFFFFull;
    constexpr auto page_1gb_mask = 0x3FFFFFFFull;

    enum class e_pt_protection {
        none,
        read_write,
        read_write_execute
    };

    struct pt_entries_t {
        pml4e m_pml4e;
        pdpte m_pdpte;
        pde m_pde;
        pte m_pte;
    };

    class c_paging {
    public:
        c_paging( ) { }
        ~c_paging( ) { }

        std::uint64_t m_directory_table_base{ };
        std::uint64_t m_physical_mask{ };
        std::uint64_t m_validation_va{ };
        std::vector<std::uint8_t> m_validation_bytes;

        bool load_validation_bytes( ) {
            m_validation_va = g_pdb->m_module_base;
            if ( !m_validation_va )
                return false;

            m_validation_bytes.assign( 0x200, 0 );
            return read_ntoskrnl_header( m_validation_bytes );
        }

        bool has_pml4_self_reference( std::uint64_t cr3 ) const {
            const auto self_pfn = cr3 >> page_shift;

            for ( auto idx = 256ull; idx < 512; ++idx ) {
                pml4e entry{};
                if ( !g_driver->read_physical_memory(
                    cr3 + idx * sizeof( pml4e ), &entry, sizeof( entry ) ) )
                    break;

                if ( entry.hard.present && entry.hard.pfn == self_pfn )
                    return true;
            }

            return false;
        }

        bool is_cr3_plausible( std::uint64_t cr3 ) const {
            cr3 &= ~0xFull;
            if ( !cr3 || ( cr3 & 0xFFF ) )
                return false;

            if ( ( cr3 >> 0x38 ) == 0x40 )
                return false;

            if ( !utility::is_physical_address_valid( cr3, page_4kb_size ) )
                return false;

            return has_pml4_self_reference( cr3 );
        }

        bool validate_system_cr3( std::uint64_t cr3 ) const {
            if ( !is_cr3_plausible( cr3 ) )
                return false;

            if ( !m_validation_va || m_validation_bytes.size( ) < 2 )
                return false;

            return cr3_maps_va(
                cr3,
                m_validation_va,
                m_validation_bytes.data( ),
                m_validation_bytes.size( )
            );
        }

        bool setup( ) {
            m_physical_mask = get_physical_address_mask( );
            const auto cpu_vendor = utility::detect_cpu_vendor( );
            logging::print( oxorany( "[mapper] cpu vendor: %s" ), utility::vendor_name( cpu_vendor ) );

            if ( !load_validation_bytes( ) ) {
                logging::print( oxorany( "[mapper] failed to load ntoskrnl validation header" ) );
                return false;
            }

            logging::print( oxorany( "[mapper] trying kpcr scan" ) );
            m_directory_table_base = scan_cr3_kpcr( );
            if ( m_directory_table_base && !validate_system_cr3( m_directory_table_base ) ) {
                logging::print(
                    oxorany( "[mapper] rejected kpcr cr3 0x%llx (failed ntoskrnl validation)" ),
                    m_directory_table_base
                );
                m_directory_table_base = 0;
            }

            if ( !m_directory_table_base ) {
                logging::print( oxorany( "[mapper] trying pml4 self-reference scan" ) );
                m_directory_table_base = scan_cr3_self_reference( );
            }

            if ( !m_directory_table_base ) {
                logging::print( oxorany( "[mapper] trying ntoskrnl header bruteforce" ) );
                m_directory_table_base = scan_cr3_for_mapping( );
            }

            if ( !m_directory_table_base || !validate_system_cr3( m_directory_table_base ) ) {
                logging::print( oxorany( "[mapper] failed to find validated system cr3" ) );
                m_directory_table_base = 0;
                return false;
            }

            logging::print( oxorany( "[mapper] system cr3: 0x%llx" ), m_directory_table_base );
            return true;
        }

        static std::uint64_t get_physical_address_mask( ) {
            int regs[ 4 ]{ };
            __cpuid( regs, 0x80000000 );
            const auto max_ext = static_cast< unsigned >( regs[ 0 ] );
            unsigned phys_bits = 36;
            if ( max_ext >= 0x80000008 ) {
                __cpuid( regs, 0x80000008 );
                const auto b = regs[ 0 ] & 0xFF;
                if ( b >= 32 && b <= 52 )
                    phys_bits = b;
            }
            return phys_bits >= 63 ? ~0ULL : ( ( 1ULL << phys_bits ) - 1ULL );
        }

        std::uint64_t scan_cr3_self_reference_range(
            std::uint64_t start_pfn,
            std::uint64_t end_pfn,
            std::uint64_t target_va,
            const std::uint8_t* expected,
            std::size_t expected_size
        ) {
            for ( auto pfn = start_pfn; pfn < end_pfn; ++pfn ) {
                const auto candidate_cr3 = pfn << page_shift;
                if ( !candidate_cr3 )
                    continue;

                if ( !utility::is_physical_address_valid( candidate_cr3, page_4kb_size ) )
                    continue;

                pml4e first{};
                if ( !g_driver->read_physical_memory( candidate_cr3, &first, sizeof( first ) ) )
                    continue;

                if ( !first.hard.present )
                    continue;

                auto has_self_ref = false;
                for ( auto idx = 256ull; idx < 512; ++idx ) {
                    pml4e entry{};
                    if ( !g_driver->read_physical_memory(
                        candidate_cr3 + idx * sizeof( pml4e ), &entry, sizeof( entry ) ) )
                        break;

                    if ( entry.hard.present && entry.hard.pfn == pfn ) {
                        has_self_ref = true;
                        break;
                    }
                }

                if ( !has_self_ref )
                    continue;

                if ( !target_va || !expected || !expected_size )
                    continue;

                if ( !cr3_maps_va( candidate_cr3, target_va, expected, expected_size ) )
                    continue;

                logging::print(
                    oxorany( "[mapper] self-ref cr3 hit pfn=0x%llx cr3=0x%llx" ),
                    pfn,
                    candidate_cr3
                );
                return candidate_cr3;
            }

            return 0;
        }

        std::uint64_t scan_cr3_self_reference( ) {
            if ( !m_validation_va || m_validation_bytes.size( ) < 2 )
                return 0;

            struct range_t {
                std::uint64_t m_start_pfn;
                std::uint64_t m_end_pfn;
            };

            const range_t ranges[ ] = {
                { 0x1A0, 0x1D0 },
                { 0x100, 0x40000 },
            };

            for ( const auto& range : ranges ) {
                logging::print(
                    oxorany( "[mapper] self-ref scan pfn=0x%llx-0x%llx" ),
                    range.m_start_pfn,
                    range.m_end_pfn
                );

                const auto found = scan_cr3_self_reference_range(
                    range.m_start_pfn,
                    range.m_end_pfn,
                    m_validation_va,
                    m_validation_bytes.data( ),
                    m_validation_bytes.size( )
                );
                if ( found )
                    return found;
            }

            return 0;
        }

        std::uint64_t scan_cr3_for_mapping( ) {
            if ( !m_validation_va || m_validation_bytes.size( ) < 2 )
                return 0;

            return scan_cr3_for_mapping(
                m_validation_va,
                m_validation_bytes.data( ),
                m_validation_bytes.size( )
            );
        }

        bool read_ntoskrnl_header( std::vector<std::uint8_t>& header ) {
            const auto& pe_path = g_pdb->get_pe_path( );
            if ( pe_path.empty( ) )
                return false;

            std::ifstream file( pe_path, std::ios::binary );
            if ( !file.is_open( ) )
                return false;

            file.read( reinterpret_cast< char* >( header.data( ) ), header.size( ) );
            return file.gcount( ) >= 2 && header[ 0 ] == 'M' && header[ 1 ] == 'Z';
        }

        std::uint64_t scan_cr3_for_mapping(
            std::uint64_t target_va,
            const std::uint8_t* expected,
            std::size_t expected_size
        ) {
            const auto max_pfn = ( m_physical_mask >> page_shift ) + 1;
            const auto scan_limit = min( max_pfn, 0x40000ULL );

            std::atomic<std::uint64_t> found_cr3{ 0 };
            std::atomic<bool> found{ false };

            const auto thread_count = max( 1u, std::thread::hardware_concurrency( ) );
            const auto chunk = scan_limit / thread_count;
            std::vector<std::thread> workers;
            workers.reserve( thread_count );

            for ( std::uint32_t idx = 0; idx < thread_count; ++idx ) {
                const auto start = idx * chunk;
                const auto end = idx + 1 == thread_count ? scan_limit : ( idx + 1 ) * chunk;
                workers.emplace_back( [ &, start, end ]( ) {
                    scan_cr3_worker( start, end, target_va, expected, expected_size, found_cr3, found );
                } );
            }

            for ( auto& worker : workers )
                worker.join( );

            return found.load( ) ? found_cr3.load( ) : 0;
        }

        std::uint64_t scan_cr3_kpcr( ) {
            auto page_buffer = std::make_unique<std::uint8_t[]>( page_4kb_size );
            for ( std::uint64_t page = 0; page < 0x20000000; page += page_4kb_size ) {
                if ( !g_driver->read_physical_memory( page, page_buffer.get( ), page_4kb_size ) )
                    continue;

                if ( page_buffer[ 0 ] != 0xE9 || page_buffer[ 1 ] != 0x4D ||
                    page_buffer[ 2 ] != 0x06 || page_buffer[ 3 ] != 0x00 )
                    continue;

                const auto dtb = *reinterpret_cast< std::uint64_t* >( page_buffer.get( ) + 0xA0 ) & ~0xFull;
                if ( !validate_system_cr3( dtb ) )
                    continue;

                logging::print( oxorany( "[mapper] kpcr signature hit cr3=0x%llx page=0x%llx" ), dtb, page );
                return dtb;
            }

            logging::print( oxorany( "[mapper] trying kpcr dtb-at-0xA0 scan (amd fallback)" ) );
            for ( std::uint64_t page = 0; page < 0x20000000; page += page_4kb_size ) {
                if ( !g_driver->read_physical_memory( page, page_buffer.get( ), page_4kb_size ) )
                    continue;

                const auto dtb = *reinterpret_cast< std::uint64_t* >( page_buffer.get( ) + 0xA0 ) & ~0xFull;
                if ( !validate_system_cr3( dtb ) )
                    continue;

                logging::print( oxorany( "[mapper] kpcr dtb-at-0xA0 hit cr3=0x%llx page=0x%llx" ), dtb, page );
                return dtb;
            }

            return 0;
        }

        void scan_cr3_worker(
            std::uint64_t start_pfn,
            std::uint64_t end_pfn,
            std::uint64_t target_va,
            const std::uint8_t* expected,
            std::size_t expected_size,
            std::atomic<std::uint64_t>& found_cr3,
            std::atomic<bool>& found
        ) {
            if ( found.load( std::memory_order_acquire ) )
                return;

            for ( auto pfn = start_pfn; pfn < end_pfn; ++pfn ) {
                if ( found.load( std::memory_order_acquire ) )
                    return;

                const auto candidate_cr3 = pfn << page_shift;
                if ( !candidate_cr3 )
                    continue;

                if ( !utility::is_physical_address_valid( candidate_cr3, page_4kb_size ) )
                    continue;

                pml4e pml4{};
                if ( !g_driver->read_physical_memory( candidate_cr3, &pml4, sizeof( pml4e ) ) )
                    continue;

                if ( !pml4.hard.present || !pml4.hard.pfn || pml4.hard.pfn >= end_pfn )
                    continue;

                auto has_self_ref = false;
                for ( auto idx = 256ull; idx < 512; ++idx ) {
                    pml4e entry{};
                    if ( !g_driver->read_physical_memory(
                        candidate_cr3 + idx * sizeof( pml4e ), &entry, sizeof( entry ) ) )
                        break;

                    if ( entry.hard.present && entry.hard.pfn == pfn ) {
                        has_self_ref = true;
                        break;
                    }
                }

                if ( !has_self_ref )
                    continue;

                if ( !cr3_maps_va( candidate_cr3, target_va, expected, expected_size ) )
                    continue;

                std::uint64_t expected_value = 0;
                if ( found_cr3.compare_exchange_strong( expected_value, candidate_cr3,
                    std::memory_order_release, std::memory_order_relaxed ) ) {
                    found.store( true, std::memory_order_release );
                }

                return;
            }
        }

        bool cr3_maps_va(
            std::uint64_t cr3,
            std::uint64_t address,
            const std::uint8_t* expected,
            std::size_t expected_size
        ) const {
            virt_addr_t va{ address };

            pml4e pml4{};
            if ( !g_driver->read_physical_memory( cr3 + va.pml4e_index * sizeof( pml4e ), &pml4, sizeof( pml4e ) ) )
                return false;
            if ( !pml4.hard.present || !pml4.hard.pfn )
                return false;

            const auto pdpt_pa = pml4.hard.pfn << page_shift;
            if ( !utility::is_physical_address_valid( pdpt_pa, page_4kb_size ) )
                return false;

            pdpte pdpt{};
            if ( !g_driver->read_physical_memory( pdpt_pa + va.pdpte_index * sizeof( pdpte ),
                &pdpt, sizeof( pdpte ) ) )
                return false;
            if ( !pdpt.hard.present || !pdpt.hard.pfn )
                return false;

            std::uint64_t page_pa = 0;
            std::uint64_t page_offset = 0;

            if ( pdpt.hard.page_size ) {
                page_pa = pdpt.hard.pfn << page_shift;
                page_offset = address & page_1gb_mask;
            }
            else {
                const auto pd_pa = pdpt.hard.pfn << page_shift;
                if ( !utility::is_physical_address_valid( pd_pa, page_4kb_size ) )
                    return false;

                pde pd{};
                if ( !g_driver->read_physical_memory( pd_pa + va.pde_index * sizeof( pde ),
                    &pd, sizeof( pde ) ) )
                    return false;
                if ( !pd.hard.present || !pd.hard.pfn )
                    return false;

                if ( pd.hard.page_size ) {
                    page_pa = pd.hard.pfn << page_shift;
                    page_offset = address & page_2mb_mask;
                }
                else {
                    const auto pt_pa = pd.hard.pfn << page_shift;
                    if ( !utility::is_physical_address_valid( pt_pa, page_4kb_size ) )
                        return false;

                    pte pt{};
                    if ( !g_driver->read_physical_memory( pt_pa + va.pte_index * sizeof( pte ),
                        &pt, sizeof( pte ) ) )
                        return false;
                    if ( !pt.hard.present || !pt.hard.pfn )
                        return false;

                    page_pa = pt.hard.pfn << page_shift;
                    page_offset = address & page_4kb_mask;
                }
            }

            if ( !utility::is_physical_address_valid( page_pa + page_offset, 0x40 ) )
                return false;

            const auto read_size = min( expected_size, static_cast< std::size_t >( 0x40 ) );
            std::uint8_t buffer[ 0x40 ]{ };
            if ( !g_driver->read_physical_memory( page_pa + page_offset, buffer, read_size ) )
                return false;

            return memcmp( buffer, expected, read_size ) == 0;
        }

        std::uint64_t translate_linear( std::uint64_t addr, std::uint32_t* page_size = 0 ) {
            pt_entries_t pt_entries;
            if ( !hyperspace_entries( pt_entries, addr ) )
                return false;

            if ( pt_entries.m_pdpte.hard.page_size ) {
                if ( page_size ) *page_size = page_1gb_size;
                const auto pa = ( pt_entries.m_pdpte.hard.pfn << 12 ) + ( addr & page_1gb_mask );
                if ( !utility::is_physical_address_valid( pa, page_4kb_size ) )
                    return 0;
                return pa;
            }

            if ( pt_entries.m_pde.hard.page_size ) {
                if ( page_size ) *page_size = page_2mb_size;
                const auto pa = ( pt_entries.m_pde.hard.pfn << 12 ) + ( addr & page_2mb_mask );
                if ( !utility::is_physical_address_valid( pa, page_4kb_size ) )
                    return 0;
                return pa;
            }

            if ( page_size ) *page_size = page_4kb_size;
            const auto pa = ( pt_entries.m_pte.hard.pfn << 12 ) + ( addr & page_4kb_mask );
            if ( !utility::is_physical_address_valid( pa, page_4kb_size ) )
                return 0;
            return pa;
        }

        std::uint64_t get_pte_address( std::uint64_t addr ) {
            pt_entries_t entries{};
            if ( !hyperspace_entries( entries, addr ) )
                return 0;

            if ( entries.m_pdpte.hard.page_size || entries.m_pde.hard.page_size )
                return 0;

            return ( entries.m_pde.hard.pfn << page_shift ) +
                ( virt_addr_t{ addr }.pte_index * sizeof( pte ) );
        }

        std::uint32_t get_page_size( std::uint64_t addr ) {
            pt_entries_t pt_entries;
            if ( !hyperspace_entries( pt_entries, addr ) )
                return false;

            if ( pt_entries.m_pdpte.hard.page_size )
                return page_1gb_size;

            if ( pt_entries.m_pde.hard.page_size )
                return page_2mb_size;
            return page_4kb_size;
        }

        e_pt_protection get_page_protect( std::uint64_t addr ) {
            pt_entries_t pt_entries;
            if ( !hyperspace_entries( pt_entries, addr ) )
                return e_pt_protection::none;

            if ( pt_entries.m_pte.hard.read_write )
                return e_pt_protection::read_write;
            if ( !pt_entries.m_pte.hard.no_execute )
                return e_pt_protection::read_write_execute;

            return e_pt_protection::none;
        }

        bool split_2mb_to_4kb( std::uint64_t address ) {
            pt_entries_t entries{};
            if ( !hyperspace_entries( entries, address ) )
                return false;

            if ( !entries.m_pde.hard.present || !entries.m_pde.hard.page_size )
                return false;

            auto new_pt_va = nt::mm_allocate_independent_pages( page_4kb_size );
            if ( !new_pt_va ) return false;
            nt::memset( new_pt_va, 0, page_4kb_size );

            const auto new_pt_pa = mmu::virtual_to_physical(
                reinterpret_cast< std::uint64_t >( new_pt_va ) );
            if ( !new_pt_pa ) return false;

            const auto base_pfn = entries.m_pde.hard.pfn;
            for ( auto idx = 0u; idx < 512u; ++idx ) {
                pte entry{};
                entry.hard.present = 1;
                entry.hard.read_write = entries.m_pde.hard.read_write;
                entry.hard.user_supervisor = entries.m_pde.hard.user_supervisor;
                entry.hard.page_write_through = entries.m_pde.hard.page_write_through;
                entry.hard.cached_disable = entries.m_pde.hard.cached_disable;
                entry.hard.global = entries.m_pde.hard.global;
                entry.hard.no_execute = 0;
                entry.hard.pfn = base_pfn + idx;

                const auto pte_pa = new_pt_pa + ( idx * sizeof( pte ) );
                if ( !g_driver->write_physical_memory( pte_pa, &entry, sizeof( pte ) ) )
                    return false;
            }

            pde new_pde{};
            new_pde.hard.present = 1;
            new_pde.hard.read_write = entries.m_pde.hard.read_write;
            new_pde.hard.user_supervisor = entries.m_pde.hard.user_supervisor;
            new_pde.hard.page_write_through = entries.m_pde.hard.page_write_through;
            new_pde.hard.cached_disable = entries.m_pde.hard.cached_disable;
            new_pde.hard.page_size = 0;
            new_pde.hard.no_execute = 0;
            new_pde.hard.pfn = new_pt_pa >> page_shift;

            virt_addr_t va{ address };
            if ( !write_pt_entry( entries.m_pdpte, va.pde_index, new_pde ) )
                return false;

            nt::flush_caches( new_pt_va );
            return true;
        }

        bool split_1gb_to_4kb( std::uint64_t address ) {
            pt_entries_t entries{};
            if ( !hyperspace_entries( entries, address ) )
                return false;

            if ( !entries.m_pdpte.hard.present || !entries.m_pdpte.hard.page_size )
                return false;

            auto new_pd_va = nt::mm_allocate_independent_pages( page_4kb_size );
            if ( !new_pd_va ) return false;

            const auto new_pd_pa = mmu::virtual_to_physical(
                reinterpret_cast< std::uint64_t >( new_pd_va ) );
            if ( !new_pd_pa ) return false;

            const auto base_pfn = entries.m_pdpte.hard.pfn;
            for ( auto pd_idx = 0u; pd_idx < 512u; ++pd_idx ) {
                auto new_pt_va = nt::mm_allocate_independent_pages( page_4kb_size );
                if ( !new_pt_va ) return false;

                const auto new_pt_pa = mmu::virtual_to_physical(
                    reinterpret_cast< std::uint64_t >( new_pt_va ) );
                if ( !new_pt_pa ) return false;

                const auto pd_base_pfn = base_pfn + ( pd_idx * 512u );
                for ( auto pt_idx = 0u; pt_idx < 512u; ++pt_idx ) {
                    pte entry{};
                    entry.hard.present = 1;
                    entry.hard.read_write = entries.m_pdpte.hard.read_write;
                    entry.hard.user_supervisor = entries.m_pdpte.hard.user_supervisor;
                    entry.hard.page_write_through = entries.m_pdpte.hard.page_write_through;
                    entry.hard.cached_disable = entries.m_pdpte.hard.cached_disable;
                    entry.hard.no_execute = 0;
                    entry.hard.pfn = pd_base_pfn + pt_idx;

                    const auto pte_pa = new_pt_pa + ( pt_idx * sizeof( pte ) );
                    if ( !g_driver->write_physical_memory( pte_pa, &entry, sizeof( pte ) ) )
                        return false;
                }

                pde pd_entry{};
                pd_entry.hard.present = 1;
                pd_entry.hard.read_write = entries.m_pdpte.hard.read_write;
                pd_entry.hard.user_supervisor = entries.m_pdpte.hard.user_supervisor;
                pd_entry.hard.page_write_through = entries.m_pdpte.hard.page_write_through;
                pd_entry.hard.cached_disable = entries.m_pdpte.hard.cached_disable;
                pd_entry.hard.page_size = 0;
                pd_entry.hard.no_execute = 0;
                pd_entry.hard.pfn = new_pt_pa >> page_shift;

                const auto pde_pa = new_pd_pa + ( pd_idx * sizeof( pde ) );
                if ( !g_driver->write_physical_memory( pde_pa, &pd_entry, sizeof( pde ) ) )
                    return false;
            }

            pdpte new_pdpte{};
            new_pdpte.hard.present = 1;
            new_pdpte.hard.read_write = entries.m_pdpte.hard.read_write;
            new_pdpte.hard.user_supervisor = entries.m_pdpte.hard.user_supervisor;
            new_pdpte.hard.page_write_through = entries.m_pdpte.hard.page_write_through;
            new_pdpte.hard.cached_disable = entries.m_pdpte.hard.cached_disable;
            new_pdpte.hard.page_size = 0;
            new_pdpte.hard.no_execute = 0;
            new_pdpte.hard.pfn = new_pd_pa >> page_shift;

            virt_addr_t va{ address };
            if ( !write_pt_entry( entries.m_pml4e, va.pdpte_index, new_pdpte ) )
                return false;

            return true;
        }

        bool read_virtual_memory( std::uint64_t addr, void* buf, std::size_t size ) {
            auto remaining = size;
            auto dst = reinterpret_cast< std::uint8_t* >( buf );
            auto current_va = addr;

            while ( remaining > 0 ) {
                auto pa = translate_linear( current_va );
                if ( !pa ) return false;

                const auto page_offset = current_va & 0xFFF;
                const auto chunk = min( remaining, 0x1000 - page_offset );

                if ( !g_driver->read_physical_memory( pa, dst, chunk ) )
                    return false;

                current_va += chunk;
                dst += chunk;
                remaining -= chunk;
            }

            return true;
        }

        bool hyperspace_entries( pt_entries_t& entries, std::uint64_t address ) {
            virt_addr_t va{ address };

            if ( !g_driver->read_physical_memory(
                m_directory_table_base + ( va.pml4e_index * sizeof( pml4e ) ),
                &entries.m_pml4e, sizeof( pml4e ) ) )
                return false;

            if ( !entries.m_pml4e.hard.present )
                return false;

            if ( !g_driver->read_physical_memory(
                ( entries.m_pml4e.hard.pfn << 12 ) + ( sizeof( pdpte ) * va.pdpte_index ),
                &entries.m_pdpte, sizeof( pdpte ) ) )
                return false;

            if ( !entries.m_pdpte.hard.present )
                return false;

            if ( entries.m_pdpte.hard.page_size )
                return true;

            if ( !g_driver->read_physical_memory(
                ( entries.m_pdpte.hard.pfn << 12 ) + ( sizeof( pde ) * va.pde_index ),
                &entries.m_pde, sizeof( pde ) ) )
                return false;

            if ( !entries.m_pde.hard.present )
                return false;

            if ( entries.m_pde.hard.page_size )
                return true;

            if ( !g_driver->read_physical_memory(
                ( entries.m_pde.hard.pfn << page_shift ) + ( va.pte_index * sizeof( pte ) ),
                &entries.m_pte, sizeof( pte ) ) )
                return false;

            if ( !entries.m_pte.hard.present )
                return false;

            return true;
        }

    private:
        template<typename parent_t, typename entry_t>
        bool write_pt_entry( const parent_t& parent, std::size_t index, const entry_t& entry ) {
            const auto pa = ( parent.hard.pfn << 12 ) + ( index * sizeof( entry_t ) );
            if ( !utility::is_physical_address_valid( pa, sizeof( entry_t ) ) )
                return false;
            return g_driver->write_physical_memory( pa, &entry, sizeof( entry_t ) );
        }
    };
}
