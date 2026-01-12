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

        let filter = "outbound and tcp.DstPort == 443 and tcp.PayloadLength > 0";
        let flags = WinDivertFlags::default();

        let divert = WinDivert::network(filter, 1000, flags)
            .expect("could not create divert");


        let mut buffer = vec!(0u8; 65535);


        let domain_bytes = domain.as_bytes();

        println!("Domain: {:?}; Len: {:?}", domain_bytes, domain_bytes.len());


        loop {
            let mut packet = divert.recv(Some(&mut buffer)).expect("Recv failed");

            let mut seq_delta: HashMap<FlowKey, i32> = HashMap::new();
            let found = packet.data.windows(domain_bytes.len()).any(|w| w == domain_bytes);
            let mut data_mut = packet.data.to_mut();

            let mut tcp_header: *mut WINDIVERT_TCPHDR = std::ptr::null_mut();
            let mut payload: *mut c_void = std::ptr::null_mut();


            unsafe {
                WinDivertHelperParsePacket(
                    packet.data.as_ptr() as *const c_void,
                    packet.data.len() as u32,
                    null_mut(), null_mut(), null_mut(),
                    null_mut(), null_mut(),
                    &mut tcp_header as *mut _ as *mut _,
                    null_mut(),
                    &mut payload as *mut _ as *mut _,
                    &mut payload_len,
                    null_mut(), null_mut(),
                );
            }



            if packet.address.Direction == 1 {
                if let Some(tcp) = unsafe { tcp_header.as_mut() } {

                    let key = FlowKey {
                        src: packet.address.dst_addr().unwrap(),
                        dst: packet.address.src_addr().unwrap(),
                        sport: u16::from_be(tcp.dst_port()),
                        dport: u16::from_be(tcp.src_port()),
                    };

                    if let Some(delta) = SEQ_DELTA.lock().unwrap().get(&key) {
                        let ack = u32::from_be(tcp.ack_number());
                        tcp.set_ack_number((ack - *delta as u32).to_be());
                        packet.recalculate_checksums(ChecksumFlags::new()).ok();
                    }
                }

                divert.send(&packet).ok();
                continue;
            }





            if found {
                println!("Packet to target ({})",  domain);




                if bias == 0 || bias >= payload_len as usize {
                    continue;
                }


                let offset = (payload as usize) - (data_mut.as_ptr() as usize);

                println!("Headers for 0 to {} bytes", offset);
                println!("TCP Header: {:?}", tcp_header);
                println!("Payload Length: {}", payload_len);
                println!("Payload: {:?} \n", payload);

                let mut data2 = Vec::new();

                data2.extend_from_slice(&data_mut[0..offset]);
                data2.extend_from_slice(&data_mut[offset + bias..]);


                let mut packet2 = unsafe { WinDivertPacket::<NetworkLayer>::new(data2) };
                packet2.address = packet.address.clone();

                if let Some(tcp) = unsafe { tcp_header.as_ref() } {
                    let key = FlowKey {
                        src: packet.address.src_addr().unwrap(),
                        dst: packet.address.dst_addr().unwrap(),
                        sport: u16::from_be(tcp.src_port()),
                        dport: u16::from_be(tcp.dst_port()),
                    };

                    *SEQ_DELTA.lock().unwrap()
                        .entry(key)
                        .or_insert(0) += bias as i32;
                }



                let data2_mut = packet2.data.to_mut();



                data_mut.truncate(offset + bias);

                let ip = unsafe { &mut *(data_mut.as_mut_ptr() as *mut WINDIVERT_IPHDR) };
                ip.set_length((data_mut.len() as u16).to_be());


                let ip2 = unsafe { &mut *(data2_mut.as_mut_ptr() as *mut WINDIVERT_IPHDR) };
                ip2.set_length((data2_mut.len() as u16).to_be());



                packet.recalculate_checksums(ChecksumFlags::new()).ok();
                packet2.recalculate_checksums(ChecksumFlags::new()).ok();

                println!("Packet1 len: {}", packet.data.len());
                divert.send(&packet).expect("Error for send packet");
                println!("Packet 1 sent");
                println!("Packet2 len: {}", packet2.data.len());
                divert.send(&packet2).expect("Error for send packet");
                println!("Packet 2 sent");

                if let Some(tcp) = unsafe { tcp_header.as_ref() } {
                    if tcp.fin() || tcp.rst() {
                        let key = FlowKey {
                            src: packet.address.src_addr().unwrap(),
                            dst: packet.address.dst_addr().unwrap(),
                            sport: u16::from_be(tcp.src_port()),
                            dport: u16::from_be(tcp.dst_port()),
                        };

                        SEQ_DELTA.lock().unwrap().remove(&key);
                        s
                    }
                }

            }



        }


    }

}
