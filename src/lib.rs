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
    use windivert_sys::header::{WINDIVERT_TCPHDR, WINDIVERT_IPHDR};
    use windivert_sys::ChecksumFlags;
    use std::ptr::{null, null_mut};
    use std::ffi::c_void;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::sync::Mutex;



    #[derive(Hash, Eq, PartialEq, Clone, Debug)]
    struct FlowKey {
        src: Ipv4Addr,
        dst: Ipv4Addr,
        sport: u16,
        dport: u16,
    }



    #[pyfunction]
    fn interception(domain: String, bias: usize) -> PyResult<Vec<u8>> {

        let filter = "outbound and tcp.DstPort == 80 and tcp.PayloadLength > 0";
        let flags = WinDivertFlags::default();

        let divert = WinDivert::network(filter, 1000, flags)
            .expect("could not create divert");


        let mut buffer = vec!(0u8; 65535);


        let domain_bytes = domain.as_bytes();

        println!("Domain: {:?}; Len: {:?}", domain_bytes, domain_bytes.len());


        loop {
            let mut packet = divert
                .recv(Some(&mut buffer))
                .expect("Recv failed");

            let found = packet
                .data
                .windows(domain_bytes.len())
                .any(|w| w == domain_bytes);

            let mut data_mut = packet.data.to_mut();

            if found {
                println!("Packet to target ({})", domain);
                println!("Data: {:?}", &data_mut);

                let mut tcp_header: *mut WINDIVERT_TCPHDR = std::ptr::null_mut();
                let mut payload: *mut c_void = std::ptr::null_mut();
                let mut payload_len: u32 = 0;

                let mut tcp_header2: *mut WINDIVERT_TCPHDR = std::ptr::null_mut();
                let mut payload2: *mut c_void = std::ptr::null_mut();
                let mut payload_len2: u32 = 0;

                unsafe {
                    WinDivertHelperParsePacket(
                        data_mut.as_ptr() as *const c_void,
                        data_mut.len() as u32,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        &mut tcp_header as *mut _ as *mut _,
                        std::ptr::null_mut(),
                        &mut payload as *mut _ as *mut _,
                        &mut payload_len,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    );
                }

                if bias == 0 || bias >= payload_len as usize {
                    continue;
                }

                let offset = (payload as usize) - (data_mut.as_ptr() as usize);

                println!("Data (utf-8): {:?}", String::from_utf8_lossy( &data_mut[offset..offset+payload_len as usize].to_vec()));
                println!("Headers for 0 to {} bytes", offset);
                println!("TCP Header: {:?}", tcp_header);
                println!("Payload Length: {}", payload_len);
                println!("Payload: {:?}\n", payload);

                let mut data2 = Vec::new();

                data2.extend_from_slice(&data_mut[0..offset]);
                data2.extend_from_slice(&data_mut[offset + bias..]);

                let mut packet2 = unsafe {
                    WinDivertPacket::<NetworkLayer>::new(data2)
                };
                packet2.address = packet.address.clone();

                let data2_mut = packet2.data.to_mut();

                unsafe {
                    WinDivertHelperParsePacket(
                        data2_mut.as_ptr() as *const c_void,
                        data2_mut.len() as u32,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        &mut tcp_header2 as *mut _ as *mut _,
                        std::ptr::null_mut(),
                        &mut payload2 as *mut _ as *mut _,
                        &mut payload_len2,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                    );
                }

                data_mut.truncate(offset + bias);

                let ip = unsafe {
                    &mut *(data_mut.as_mut_ptr() as *mut WINDIVERT_IPHDR)
                };
                ip.set_length((data_mut.len() as u16).to_be());

                let ip2 = unsafe {
                    &mut *(data2_mut.as_mut_ptr() as *mut WINDIVERT_IPHDR)
                };
                ip2.set_length((data2_mut.len() as u16).to_be());

                if let Some(tcp2) = unsafe { tcp_header2.as_mut() } {
                    let old_seq = u32::from_be(tcp2.seq_number());
                    tcp2.set_seq_number((old_seq + bias as u32).to_be());
                }

                packet
                    .recalculate_checksums(ChecksumFlags::new())
                    .ok();

                packet2
                    .recalculate_checksums(ChecksumFlags::new())
                    .ok();

                println!("Packet1 len: {}", packet.data.len());
                divert.send(&packet).expect("Error for send packet");
                println!("Packet 1 sent");

                println!("Packet2 len: {}", packet2.data.len());
                divert.send(&packet2).expect("Error for send packet");
                println!("Packet 2 sent");
            }
            }



        }

    }
