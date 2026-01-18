use pyo3::prelude::*;

/// A Python module implemented in Rust.
#[pymodule]
mod cheburnet {
    use pyo3::prelude::*;
    use windivert::prelude::*;
    use windivert_sys::{WinDivertHelperParsePacket};
    use windivert_sys::header::{ WINDIVERT_TCPHDR, WINDIVERT_IPHDR, WINDIVERT_IPV6HDR };
    use windivert_sys::ChecksumFlags;
    use std::ptr::{ null_mut };
    use std::ffi::c_void;




    #[pyfunction]
    fn interception(domain: String, bias: usize) -> PyResult<Vec<u8>> {

        let filter = "outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0";
        let flags = WinDivertFlags::new();

        let divert = WinDivert::network(filter, 0, flags)
            .expect("could not create divert");


        let mut buffer = vec!(0u8; 65535);
        let domain_bytes = domain.as_bytes();

        let mut blacklist = std::collections::HashSet::new();
        blacklist.insert("neverssl.com".to_string());
        blacklist.insert("youtube.com".to_string());
        blacklist.insert("googlevideo.com".to_string());

        let mut blocklist = std::collections::HashSet::new();
        blocklist.insert("max.ru".to_string());

        println!("Domain: {:?}; Len: {:?}", domain_bytes, domain_bytes.len());


        loop {
            let mut packet = divert
                .recv(Some(&mut buffer))
                .expect("Recv failed");



            let mut ip_header: *mut WINDIVERT_IPHDR = null_mut();
            let mut ipv6_header: *mut WINDIVERT_IPV6HDR = null_mut();
            let mut tcp_header: *mut WINDIVERT_TCPHDR = null_mut();
            let mut payload: *mut c_void = null_mut();
            let mut payload_len: u32 = 0;

            unsafe {
                WinDivertHelperParsePacket(
                    packet.data.as_ptr() as *const _, packet.data.len() as u32,
                    &mut ip_header as *mut _ as *mut _, &mut ipv6_header as *mut _ as *mut _,
                    null_mut(), null_mut(), null_mut(),
                    &mut tcp_header as *mut _ as *mut _, null_mut(),
                    &mut payload as *mut _ as *mut _, &mut payload_len,
                    null_mut(), null_mut(),
                );
            }

            if tcp_header.is_null() {
                    divert.send(&packet).ok();
                    continue;
            }

            let base_ptr = packet.data.as_ptr() as usize;
            let payload_ptr = payload as usize;
            let offset = payload_ptr - base_ptr;




            unsafe {
                if !ip_header.is_null() {

                    if (*ip_header).ttl == 121 {
                        divert.send(&packet).ok();
                        println!("121");
                        continue;
                    }

                } else if !ipv6_header.is_null() {

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

            let mut need_fragmentation = false;

            if payload_len > 0 && payload_len < 3000 {
                let payload_slice = unsafe {
                    std::slice::from_raw_parts(payload as *const u8, payload_len as usize)
                };


                for domain in &blacklist {
                    if payload_slice.windows(domain.len()).any(|w| w == domain.as_bytes()) {
                        need_fragmentation = true;
                        break;
                    }
                }
            }

            let mut is_blocked = false;

            for domain in &blocklist {
                is_blocked = packet.data.windows(domain.len()).any(|w| w == domain.as_bytes());
                if is_blocked {
                    println!("{} у нас в бане (иди нахуй)", domain);
                }
            }




            let data_mut = packet.data.to_mut();

            if is_blocked {

                let mut rst_data = packet.data.to_vec();

                unsafe {
                    let mut ip_header: *mut WINDIVERT_IPHDR = null_mut();
                    let mut tcp_header: *mut WINDIVERT_TCPHDR = null_mut();

                    WinDivertHelperParsePacket(
                        rst_data.as_ptr() as *const _, rst_data.len() as u32,
                        &mut ip_header as *mut _ as *mut _, null_mut(), null_mut(), null_mut(), null_mut(),
                        &mut tcp_header as *mut _ as *mut _, null_mut(), null_mut(), null_mut(), null_mut(), null_mut()
                    );

                    if !ip_header.is_null() && !tcp_header.is_null() {
                        let src = (*ip_header).src_addr();
                        (*ip_header).set_src_addr((*ip_header).dst_addr());
                        (*ip_header).set_dst_addr(src);

                        let src_p = (*tcp_header).src_port();
                        (*tcp_header).set_src_port((*tcp_header).dst_port());
                        (*tcp_header).set_dst_port(src_p);

                        (*tcp_header).set_RST(1);
                        (*tcp_header).set_ACK(1);

                        let incoming_ack = (*tcp_header).ACK_number();
                        (*tcp_header).set_seq_number(incoming_ack);

                    }

                    let mut rst_packet = unsafe { WinDivertPacket::<NetworkLayer>::new(rst_data) };


                    rst_packet.address.set_outbound(false);
                    rst_packet.address.set_impostor(true);
                    rst_packet.recalculate_checksums(ChecksumFlags::new()).ok();


                    divert.send(&rst_packet).ok();


                    continue;
                }
            }

            if need_fragmentation {
                println!("Packet to target ({})", domain);
                println!("Data len: {:?}", data_mut.len());


                let mut bad_data = data_mut.to_vec();


                if tcp_header.is_null() { continue; }


                let safe_bias = if bias == 0 { 1 } else { bias };


                let mut data2_vec = data_mut[0..offset].to_vec();
                data2_vec.extend_from_slice(&data_mut[offset + safe_bias..]);

                let mut packet2 = unsafe { WinDivertPacket::<NetworkLayer>::new(data2_vec) };
                packet2.address = packet.address.clone();

                data_mut.truncate(offset + safe_bias);

                let mut nw_data = data_mut.clone();

                let tcp_offset = if nw_data[0] == 0x45 { 20 } else { 40 };
                let win_size_idx = tcp_offset + 14;


                nw_data[win_size_idx] = 0x00;
                nw_data[win_size_idx + 1] = 0x01;

                let mut nw_packet = unsafe { WinDivertPacket::<NetworkLayer>::new(nw_data) };

                nw_packet.address = nw_packet.address.clone();
                nw_packet.recalculate_checksums(ChecksumFlags::new()).ok();


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
                    let b_d = bad_data.as_mut_slice();
                    if b_d[0] == 0x45 {
                        d[8] = 5;
                    }
                    else {
                        b_d[7] = 5;
                    }
                    
                }


                packet.address.set_impostor(true);
                packet.address.set_outbound(true);
                packet.recalculate_checksums(ChecksumFlags::new()).ok();

                {
                    let d2 = packet2.data.to_mut();


                    let mut tcp_offset = 20;
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

                    let seq_idx = tcp_offset + 4;
                    let mut current_seq = u32::from_be_bytes([d2[seq_idx], d2[seq_idx+1], d2[seq_idx+2], d2[seq_idx+3]]);
                    current_seq += safe_bias as u32;
                    d2[seq_idx..seq_idx+4].copy_from_slice(&current_seq.to_be_bytes());
                }


                let mut bad_packet = unsafe { WinDivertPacket::<NetworkLayer>::new(bad_data) };
                bad_packet.address = bad_packet.address.clone();


                packet2.address.set_impostor(true);
                packet2.address.set_outbound(true);
                packet2.recalculate_checksums(ChecksumFlags::new()).ok();
                bad_packet.recalculate_checksums(ChecksumFlags::new()).ok();


                println!("Packet1 len: {:?}", packet.data.len());
                println!("Packet2 len: {:?}", packet2.data.len());
                println!("Packet1 data: {:?}", String::from_utf8_lossy(&packet.data[offset..packet.data.len()]));
                println!("Packet2 data: {:?}", String::from_utf8_lossy(&packet2.data[offset..packet2.data.len()]));

                println!("План скам (Send Bad Packet)");
                divert.send(&bad_packet).ok();
                divert.send(&nw_packet).ok();
                divert.send(&packet2).ok();
                divert.send(&packet).ok();
            }
            else {
                divert.send(&packet).ok();
            }

            }

        }

    }

// Code by 0b101100110010011100110001001010
// picun F6