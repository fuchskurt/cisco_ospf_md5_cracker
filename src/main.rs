use eframe::egui;
use pcap_file::{
    pcap::PcapReader,
    pcapng::{Block, PcapNgReader},
};
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use rfd::FileDialog;
use std::{
    fs::File,
    io::{BufReader, Read, Seek, SeekFrom},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
};

#[derive(Clone)]
struct OspfResult {
    index: usize,
    timestamp: String,
    result: String,
}

#[derive(Default)]
struct OspfGuiApp {
    pcap_path: String,
    running: bool,
    results: Vec<OspfResult>,
    error: String,
    shared_results: Arc<std::sync::Mutex<Vec<OspfResult>>>,
    shared_running: Arc<AtomicBool>,
    shared_progress: Arc<std::sync::Mutex<String>>,
    shared_error: Arc<std::sync::Mutex<String>>,
    stop_requested: Arc<AtomicBool>,
    started: bool,
    charset_letters: bool,
    charset_numbers: bool,
    charset_symbols: bool,
    charset_custom: String,
    key_max_len: usize,
}

impl eframe::App for OspfGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
                                         ui.heading("OSPF MD5 Brute-force GUI");
                                         ui.horizontal(|ui| {
                                               ui.label("PCAP file path:");
                                               if ui.button("Browse...").clicked()
                                                  && let Some(path) =
                                                      FileDialog::new().add_filter("PCAP files",
                                                                                   &["pcap",
                                                                                     "pcapng"])
                                                                       .pick_file()
                                               {
                                                   self.pcap_path = path.display().to_string();
                                               }
                                               ui.text_edit_singleline(&mut self.pcap_path);
                                           });

                                         ui.horizontal(|ui| {
                                               ui.label("Charset:");

                                               ui.checkbox(&mut self.charset_letters,
                                                           "Upper Case Letters");
                                               ui.checkbox(&mut self.charset_numbers,
                                                           "Numbers 0-9");
                                               ui.checkbox(&mut self.charset_symbols, "Symbols");
                                               ui.label("Custom:");
                                               ui.text_edit_singleline(&mut self.charset_custom);
                                           });

                                         ui.horizontal(|ui| {
                                               ui.label("Max key length:");
                                               ui.add(egui::Slider::new(&mut self.key_max_len,
                                                                        1..=32).suffix(" chars"));
                                           });

                                         let progress =
                                             self.shared_progress.lock().unwrap().clone();
                                         if !progress.is_empty() {
                                             ui.label(format!("Progress: {}", progress));
                                         }

                                         if self.running {
                                             ui.add_enabled(false,
                                                            egui::Button::new("Cracking..."));
                                             if ui.button("Stop").clicked() {
                                                 self.stop_requested.store(true, Ordering::Relaxed);
                                             }
                                         } else if ui.button("Start Brute-force").clicked()
                                                   && !self.started
                                         {
                                             self.stop_requested.store(false, Ordering::Relaxed);
                                             *self.shared_results.lock().unwrap() = Vec::new();
                                             *self.shared_error.lock().unwrap() = String::new();
                                             self.shared_running.store(true, Ordering::Relaxed);
                                             self.started = true;

                                             let path = self.pcap_path.clone();
                                             let charset = self.effective_charset();
                                             let max_len = self.key_max_len.to_string();
                                             let shared_results = Arc::clone(&self.shared_results);
                                             let shared_running = Arc::clone(&self.shared_running);
                                             let shared_error = Arc::clone(&self.shared_error);

                                             let stop_requested = Arc::clone(&self.stop_requested);
                                             let shared_progress =
                                                 Arc::clone(&self.shared_progress);
                                             thread::spawn(move || {
                                                 let r = run_crack(&path,
                                                                   &charset,
                                                                   &max_len,
                                                                   &shared_results,
                                                                   &stop_requested,
                                                                   &shared_progress);
                                                 shared_running.store(false, Ordering::Relaxed);
                                                 if let Err(e) = r {
                                                     *shared_error.lock().unwrap() = e;
                                                 }
                                             });
                                         }

                                         // Update self.results and self.error from shared values
                                         self.running = self.shared_running.load(Ordering::Relaxed);
                                         if !self.running {
                                             self.results =
                                                 self.shared_results.lock().unwrap().clone();
                                             self.error = self.shared_error.lock().unwrap().clone();
                                             self.started = false;
                                         }

                                         if !self.error.is_empty() {
                                             ui.colored_label(egui::Color32::RED, &self.error);
                                         }

                                         egui::ScrollArea::vertical().show(ui, |ui| {
                                                                         for res in &self.results {
                                                                             ui.group(|ui| {
                        ui.label(format!("Packet {} | {}", res.index, res.timestamp));
                        ui.label(&res.result);
                    });
                                                                         }
                                                                     });
                                     });
        ctx.request_repaint();
    }
}

impl OspfGuiApp {
    fn effective_charset(&self) -> String {
        let mut charset = String::new();
        if self.charset_letters {
            charset.push_str("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }
        if self.charset_numbers {
            charset.push_str("0123456789");
        }
        if self.charset_symbols {
            charset.push_str(r#"!@#$%^&*()-_=+[]{};:'",.<>?/|\`~"#);
        }
        charset.push_str(&self.charset_custom);
        if charset.is_empty() {
            "abcdefghijklmnopqrstuvwxyz".to_string()
        } else {
            charset.chars().collect::<std::collections::BTreeSet<_>>().iter().collect()
        }
    }
}

fn parse_ipv4_offsets(eth_payload: &[u8]) -> Option<(usize, u8, usize)> {
    if eth_payload.len() < 20 {
        return None;
    }
    let ver_ihl = eth_payload[0];
    if ver_ihl >> 4 != 4 {
        return None;
    }
    let ihl = (ver_ihl & 0x0f) as usize;
    let ip_header_len = ihl * 4;
    if eth_payload.len() < ip_header_len {
        return None;
    }
    let protocol = eth_payload[9];
    let ip_payload_offset = ip_header_len;
    Some((ip_header_len, protocol, ip_payload_offset))
}

#[derive(Debug)]
struct OspfPacket {
    timestamp: std::time::Duration,
    ospf_packet: Vec<u8>,
    digest: Vec<u8>,
}

fn try_parse_ospf(data: &[u8], timestamp: u64) -> Option<OspfPacket> {
    if data.len() < 14 {
        return None;
    }
    let ethertype = u16::from_be_bytes([data[12], data[13]]);
    if ethertype != 0x0800 {
        return None;
    }
    let eth_payload = &data[14..];
    let (_, protocol, ip_payload_offset) = parse_ipv4_offsets(eth_payload)?;
    if protocol != 89 {
        return None;
    }
    let ospf_start = 14 + ip_payload_offset;
    if data.len() <= ospf_start {
        return None;
    }
    let ospf_all = &data[ospf_start..];
    if ospf_all.len() < 24 {
        return None;
    }
    let ospf_len = u16::from_be_bytes([ospf_all[2], ospf_all[3]]) as usize;
    let auth_data_len = 16;
    if ospf_all.len() < ospf_len + auth_data_len {
        return None;
    }
    Some(OspfPacket { timestamp: std::time::Duration::from_micros(timestamp),
                      ospf_packet: ospf_all[..ospf_len].to_vec(),
                      digest: ospf_all[ospf_len..ospf_len + auth_data_len].to_vec() })
}

fn extract_ospf_packets(filename: &str) -> Result<Vec<OspfPacket>, String> {
    let file = File::open(filename).map_err(|e| format!("Failed to open: {e}"))?;
    let mut reader = BufReader::new(file);

    // Read first 4 bytes to detect file type
    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic).map_err(|e| format!("Read error: {e}"))?;
    reader.seek(SeekFrom::Start(0)).map_err(|e| format!("Seek error: {e}"))?;

    let mut packets = Vec::new();

    if &magic == b"\x0A\x0D\x0D\x0A" {
        let mut pcapng = PcapNgReader::new(reader).map_err(|e| format!("PCAPNG error: {e}"))?;

        loop {
            match pcapng.next_block() {
                Some(Ok(block)) => match block {
                    Block::EnhancedPacket(epb) => {
                        let ts = epb.timestamp.as_secs() * 1_000_000
                                 + epb.timestamp.subsec_micros() as u64;

                        if let Some(pkt) = try_parse_ospf(&epb.data, ts) {
                            packets.push(pkt);
                        }
                    }
                    Block::SimplePacket(spb) => {
                        if let Some(pkt) = try_parse_ospf(&spb.data, 0) {
                            packets.push(pkt);
                        }
                    }
                    _ => {}
                },
                Some(Err(_)) => continue,
                None => break,
            }
        }
    } else {
        // It's a classic pcap file
        let mut pcap = PcapReader::new(reader).map_err(|e| format!("PCAP error: {e}"))?;
        while let Some(pkt) = pcap.next_packet() {
            let pkt = match pkt {
                Ok(p) => p,
                Err(_) => continue,
            };
            let ts = pkt.timestamp.as_secs() * 1_000_000 + pkt.timestamp.subsec_micros() as u64;

            if let Some(pkt) = try_parse_ospf(&pkt.data, ts) {
                packets.push(pkt);
            }
        }
    }

    Ok(packets)
}

fn make_md5_key(key_string: &str) -> [u8; 16] {
    let mut key = [0u8; 16];
    let bytes = key_string.as_bytes();
    let len = bytes.len().min(16);
    key[..len].copy_from_slice(&bytes[..len]);
    key
}

fn key_matches(ospf_packet: &[u8], digest: &[u8], candidate_key: &str) -> bool {
    let md5_key = make_md5_key(candidate_key);
    let mut md5_input = Vec::with_capacity(ospf_packet.len() + md5_key.len());
    md5_input.extend_from_slice(ospf_packet);
    md5_input.extend_from_slice(&md5_key);
    let computed = md5::compute(&md5_input);
    let computed_bytes: [u8; 16] = computed.into();
    digest == computed_bytes
}

fn brute_force_parallel(ospf_packet: Arc<Vec<u8>>,
                        digest: Arc<Vec<u8>>,
                        charset: Arc<Vec<u8>>,
                        max_len: usize,
                        found_flag: Arc<AtomicBool>,
                        stop_requested: &Arc<AtomicBool>,
                        shared_progress: &Arc<std::sync::Mutex<String>>)
                        -> Option<String> {
    (1..=max_len).find_map(|len| {
                     let mut prefixes = Vec::new();
                     let mut buf = vec![0u8; len];
                     for i in 0..charset.len() {
                         buf[0] = charset[i];
                         if len == 1 {
                             prefixes.push(vec![charset[i]]);
                         } else {
                             prefixes.push(buf.clone());
                         }
                     }
                     prefixes.par_iter().find_map_any(|prefix| {
                                            let mut key = prefix.clone();
                                            brute_force_recursive(&ospf_packet,
                                                                  &digest,
                                                                  &charset,
                                                                  len,
                                                                  1,
                                                                  &mut key,
                                                                  &found_flag,
                                                                  stop_requested,
                                                                  shared_progress)
                                        })
                 })
}

fn brute_force_recursive(ospf_packet: &Vec<u8>,
                         digest: &Vec<u8>,
                         charset: &Vec<u8>,
                         max_len: usize,
                         pos: usize,
                         key: &mut Vec<u8>,
                         found_flag: &Arc<AtomicBool>,
                         stop_requested: &Arc<AtomicBool>,
                         shared_progress: &Arc<std::sync::Mutex<String>>)
                         -> Option<String> {
    if found_flag.load(Ordering::Relaxed) || stop_requested.load(Ordering::Relaxed) {
        return None;
    }
    if pos == max_len {
        let candidate = String::from_utf8_lossy(key).into_owned();
        static ATOM: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = ATOM.fetch_add(1, Ordering::Relaxed);
        if n.is_multiple_of(10_000) {
            *shared_progress.lock().unwrap() = format!("Testing key: {}", candidate);
        }

        if key_matches(ospf_packet, digest, &candidate) {
            found_flag.store(true, Ordering::Relaxed);
            return Some(candidate);
        }
        return None;
    }
    for &c in charset.iter() {
        if found_flag.load(Ordering::Relaxed) || stop_requested.load(Ordering::Relaxed) {
            break;
        }
        key[pos] = c;
        if let Some(found) = brute_force_recursive(ospf_packet,
                                                   digest,
                                                   charset,
                                                   max_len,
                                                   pos + 1,
                                                   key,
                                                   found_flag,
                                                   stop_requested,
                                                   shared_progress)
        {
            return Some(found);
        }
        if found_flag.load(Ordering::Relaxed) || stop_requested.load(Ordering::Relaxed) {
            break;
        }
    }
    None
}

fn run_crack(filename: &str,
             charset: &str,
             max_len: &str,
             results: &Arc<std::sync::Mutex<Vec<OspfResult>>>,
             stop_requested: &Arc<AtomicBool>,
             shared_progress: &Arc<std::sync::Mutex<String>>)
             -> Result<(), String> {
    let max_len: usize = max_len.parse().map_err(|_| "max_len must be integer".to_owned())?;
    let charset = charset.as_bytes().to_vec();
    let ospf_packets = extract_ospf_packets(filename)?;

    if ospf_packets.is_empty() {
        return Err("No OSPF packets found.".to_owned());
    }

    let local_results: Result<Vec<OspfResult>, String> =
        ospf_packets.par_iter()
                    .enumerate()
                    .map(|(idx, pkt)| {
                        if stop_requested.load(Ordering::Relaxed) {
                            return Err("Stopped by user.".to_string());
                        }

                        let found_flag = Arc::new(AtomicBool::new(false));
                        let key = brute_force_parallel(Arc::new(pkt.ospf_packet.clone()),
                                                       Arc::new(pkt.digest.clone()),
                                                       Arc::new(charset.clone()),
                                                       max_len,
                                                       found_flag.clone(),
                                                       stop_requested,
                                                       shared_progress);

                        let timestamp = format!("{:?}", pkt.timestamp);
                        let result = if let Some(found) = key {
                            stop_requested.store(true, Ordering::Relaxed);
                            format!("✅ Found key: {}", found)
                        } else {
                            "❌ No key found (charset/length exhausted).".to_string()
                        };

                        Ok(OspfResult { index: idx + 1, timestamp, result })
                    })
                    .collect();

    let local_results = local_results?;
    results.lock().unwrap().extend(local_results);
    Ok(())
}

fn main() {
    let app = OspfGuiApp { shared_results: Arc::new(std::sync::Mutex::new(Vec::new())),
                           shared_running: Arc::new(AtomicBool::new(false)),
                           shared_error: Arc::new(std::sync::Mutex::new(String::new())),
                           shared_progress: Arc::new(std::sync::Mutex::new(String::new())),
                           stop_requested: Arc::new(AtomicBool::new(false)),
                           ..Default::default() };
    let native_options = eframe::NativeOptions::default();
    eframe::run_native("OSPF MD5 Brute-force Tool",
                       native_options,
                       Box::new(|_cc| Ok(Box::new(app)))).expect("TODO: panic message");
}
