use pyo3::prelude::*;

/// A Python module implemented in Rust.
#[pymodule]
mod cheburnet {
    use pyo3::prelude::*;
    use rayon::prelude::*;
    use std::env;
    use std::mem::replace;
    use pyo3::types::{PyBool, PyList};
    use windivert::prelude::*;
    use windivert_sys::{WinDivertHelperParsePacket};
    use windivert_sys::header::{WINDIVERT_TCPHDR, WINDIVERT_IPHDR, WINDIVERT_IPV6HDR};
    use windivert_sys::ChecksumFlags;
    use std::ptr::{null, null_mut};
    use std::ffi::c_void;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;
    use windivert_sys::*;



    #[derive(Hash, Eq, PartialEq, Clone, Debug)]
    struct FlowKey {
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
    }



    #[pyfunction]
    fn interception(domain: String, bias: usize) -> PyResult<Vec<u8>> {

        let filter = "outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0";
        let flags = WinDivertFlags::new().set_no_installs();

        let divert = WinDivert::network(filter, 0, flags)
            .expect("could not create divert");


        let mut buffer = vec!(0u8; 65535);


        let domain_bytes = domain.as_bytes();

        println!("Domain: {:?}; Len: {:?}", domain_bytes, domain_bytes.len());


        loop {
            let mut packet = divert
                .recv(Some(&mut buffer))
                .expect("Recv failed");


            let mut ip_header: *mut WINDIVERT_IPHDR = null_mut();
            let mut ipv6_header: *mut WINDIVERT_IPV6HDR = null_mut();

            unsafe {
                // Обязательно передаем нули во все ненужные поля
                WinDivertHelperParsePacket(
                    packet.data.as_ptr() as *const c_void,
                    packet.data.len() as u32,
                    &mut ip_header as *mut _ as *mut _,
                    &mut ipv6_header as *mut _ as *mut _,
                    null_mut(), null_mut(), null_mut(),
                    null_mut(), // tcp
                    null_mut(), // udp
                    null_mut(), // payload
                    null_mut(), // payload_len
                    null_mut(), null_mut(),
                );


                if !ip_header.is_null() {
                    if (*ip_header).ttl == 121 {
                        divert.send(&packet).ok();
                        println!("121");
                        continue;
                    }

                } else if !ipv6_header.is_null() {
                    // В IPv6 поле ttl часто мапится на hop_limit в структуре
                    if (*ipv6_header).hop_limit == 121 {
                        divert.send(&packet).ok();
                        println!("121");
                        continue;
                    }

                }
                else {
                    println!("IP header missing");
                }
            }

            let found = packet
                .data
                .windows(domain_bytes.len())
                .any(|w| w == domain_bytes);

            let mut data_mut = packet.data.to_mut();

            if found {
                println!("Packet to target ({})", domain);
                println!("Data len: {:?}", data_mut.len());

                let mut ip_header: *mut WINDIVERT_IPHDR = null_mut();
                let mut ipv6_header: *mut WINDIVERT_IPV6HDR = null_mut();
                let mut tcp_header: *mut WINDIVERT_TCPHDR = null_mut();
                let mut payload: *mut c_void = null_mut();
                let mut payload_len: u32 = 0;

                unsafe {
                    WinDivertHelperParsePacket(
                        data_mut.as_ptr() as *const c_void,
                        data_mut.len() as u32,
                        &mut ip_header as *mut _ as *mut _,
                        &mut ipv6_header as *mut _ as *mut _,
                        null_mut(), null_mut(), null_mut(),
                        &mut tcp_header as *mut _ as *mut _,
                        null_mut(),
                        &mut payload as *mut _ as *mut _,
                        &mut payload_len,
                        null_mut(), null_mut(),
                    );
                }

                if tcp_header.is_null() { continue; }
                let offset = (payload as usize) - (data_mut.as_ptr() as usize);


                let safe_bias = if bias == 0 { 1 } else { bias };

                // 1. СОЗДАЕМ ДАННЫЕ ДЛЯ ВТОРОГО ПАКЕТА (пока data_mut еще полный!)
                let mut data2_vec = data_mut[0..offset].to_vec();
                data2_vec.extend_from_slice(&data_mut[offset + safe_bias..]);

                let mut packet2 = unsafe { WinDivertPacket::<NetworkLayer>::new(data2_vec) };
                packet2.address = packet.address.clone();

                // 2. ОБРЕЗАЕМ ПЕРВЫЙ ПАКЕТ
                data_mut.truncate(offset + safe_bias);

                // 3. ПРАВИМ ЗАГОЛОВКИ ПЕРВОГО ПАКЕТА
                unsafe {
                    if !ip_header.is_null() {
                        (*ip_header).set_length((data_mut.len() as u16).to_be());
                    } else if !ipv6_header.is_null() {
                        let len_ptr = (ipv6_header as *mut u8).add(4) as *mut u16;
                        *len_ptr = ((data_mut.len() - 40) as u16).to_be();
                    }
                }

                {
                    let d = packet.data.to_mut();
                    if d[0] == 0x45 { // IPv4
                        d[8] = 121; // TTL
                        let len = d.len() as u16;
                        d[2..4].copy_from_slice(&len.to_be_bytes()); // Length
                    } else if (d[0] & 0xf0) == 0x60 { // IPv6
                        d[7] = 121; // Hop Limit
                        let len = (d.len() - 40) as u16;
                        d[4..6].copy_from_slice(&len.to_be_bytes()); // Payload Length
                    }
                }

                packet.address.set_impostor(true);
                packet.address.set_outbound(true);
                packet.recalculate_checksums(ChecksumFlags::new()).ok();

                // 4. ПРАВИМ ЗАГОЛОВКИ ВТОРОГО ПАКЕТА
                {
                    let d2 = packet2.data.to_mut();

                    // Сначала SEQ в TCP (находится по offset + 4)
                    let mut tcp_offset = 20; // по умолчанию для IPv4
                    if d2[0] == 0x45 {
                        d2[8] = 121; // TTL
                        let len = d2.len() as u16;
                        d2[2..4].copy_from_slice(&len.to_be_bytes());
                    } else {
                        d2[7] = 121; // Hop Limit
                        let len = (d2.len() - 40) as u16;
                        d2[4..6].copy_from_slice(&len.to_be_bytes());
                        tcp_offset = 40;
                    }

                    // Правим SEQ (он всегда через 4 байта от начала TCP заголовка)
                    let seq_idx = tcp_offset + 4;
                    let mut current_seq = u32::from_be_bytes([d2[seq_idx], d2[seq_idx+1], d2[seq_idx+2], d2[seq_idx+3]]);
                    current_seq += safe_bias as u32;
                    d2[seq_idx..seq_idx+4].copy_from_slice(&current_seq.to_be_bytes());
                }




                packet2.address.set_impostor(true);
                packet2.address.set_outbound(true);
                packet2.recalculate_checksums(ChecksumFlags::new()).ok();

                println!("Packet1 len: {:?}", packet.data.len());
                println!("Packet2 len: {:?}", packet2.data.len());
                println!("Packet1 data: {:?}", String::from_utf8_lossy(&packet.data[offset..packet.data.len()]));
                println!("Packet2 data: {:?}", String::from_utf8_lossy(&packet2.data[offset..packet2.data.len()]));


                divert.send(&packet2).ok(); // Сначала второй
                divert.send(&packet).ok();  // Потом первый
            }

            }

        }

    }
