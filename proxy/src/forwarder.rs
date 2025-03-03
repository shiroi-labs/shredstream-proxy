use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, RwLock,
    },
    thread::{Builder, JoinHandle},
    time::{Duration, SystemTime},
};

use arc_swap::ArcSwap;
use crossbeam_channel::{Receiver, RecvError};
use dashmap::DashMap;
use itertools::Itertools;
use jito_protos::trace_shred::TraceShred;
use log::{debug, error, info, warn};
use prost::Message;
use solana_entry::entry::Entry;
use solana_ledger::shred::{merkle::Shred, ReedSolomonCache, ShredType, Shredder};
use solana_metrics::{datapoint_info, datapoint_warn};
use solana_perf::{
    deduper::Deduper,
    packet::{PacketBatch, PacketBatchRecycler},
    recycler::Recycler,
};
use solana_sdk::clock::Slot;
use solana_streamer::{
    sendmmsg::{batch_send, SendPktsError},
    streamer::{self, StreamerReceiveStats},
};

use crate::{resolve_hostname_port, ShredstreamProxyError};

// values copied from https://github.com/solana-labs/solana/blob/33bde55bbdde13003acf45bb6afe6db4ab599ae4/core/src/sigverify_shreds.rs#L20
pub const DEDUPER_FALSE_POSITIVE_RATE: f64 = 0.001;
pub const DEDUPER_NUM_BITS: u64 = 637_534_199; // 76MB
pub const DEDUPER_RESET_CYCLE: Duration = Duration::from_secs(5 * 60);

/// Bind to ports and start forwarding shreds
#[allow(clippy::too_many_arguments)]
pub fn start_forwarder_threads(
    unioned_dest_sockets: Arc<ArcSwap<Vec<SocketAddr>>>, /* sockets shared between endpoint discovery thread and forwarders */
    src_addr: IpAddr,
    src_port: u16,
    num_threads: Option<usize>,
    deduper: Arc<RwLock<Deduper<2, [u8]>>>,
    metrics: Arc<ShredMetrics>,
    forward_stats: Arc<StreamerReceiveStats>,
    use_discovery_service: bool,
    debug_trace_shred: bool,
    shutdown_receiver: Receiver<()>,
    exit: Arc<AtomicBool>,
) -> Vec<JoinHandle<()>> {
    let num_threads = num_threads
        .unwrap_or_else(|| usize::from(std::thread::available_parallelism().unwrap()).max(4));

    let recycler: PacketBatchRecycler = Recycler::warmed(100, 1024);

    // multi_bind_in_range returns (port, Vec<UdpSocket>)
    let sockets =
        solana_net_utils::multi_bind_in_range(src_addr, (src_port, src_port + 1), num_threads)
            .unwrap_or_else(|_| {
                panic!("Failed to bind listener sockets. Check that port {src_port} is not in use.")
            });

    sockets
        .1
        .into_iter()
        .enumerate()
        .flat_map(|(thread_id, incoming_shred_socket)| {
            let (packet_sender, packet_receiver) = crossbeam_channel::unbounded();
            let listen_thread = streamer::receiver(
                format!("ssListen{thread_id}"),
                Arc::new(incoming_shred_socket),
                exit.clone(),
                packet_sender,
                recycler.clone(),
                forward_stats.clone(),
                Duration::default(),
                false,
                None,
                false,
            );

            let deduper = deduper.clone();
            let unioned_dest_sockets = unioned_dest_sockets.clone();
            let metrics = metrics.clone();
            let shutdown_receiver = shutdown_receiver.clone();
            let mut deshredded_entries = Vec::new();
            let exit = exit.clone();

            let send_thread = Builder::new()
                .name(format!("ssPxyTx_{thread_id}"))
                .spawn(move || {
                    let send_socket =
                        UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
                            .expect("to bind to udp port for forwarding");
                    let mut local_dest_sockets = unioned_dest_sockets.load();

                    let refresh_subscribers_tick = if use_discovery_service {
                        crossbeam_channel::tick(Duration::from_secs(30))
                    } else {
                        crossbeam_channel::tick(Duration::MAX)
                    };

                    // Track parsed Shred as reconstructed_shreds[ slot ][ fec_set_index ] -> Vec<Shred>
                    let mut all_reconstructed_shreds: HashMap<
                        Slot,
                        HashMap<u32 /* fec_set_index */, HashSet<Shred>>,
                    > = HashMap::new();

                    while !exit.load(Ordering::Relaxed) {
                        crossbeam_channel::select! {
                            // forward packets
                            recv(packet_receiver) -> maybe_packet_batch => {
                                let res = recv_from_channel_and_send_multiple_dest(
                                    maybe_packet_batch,
                                    &deduper,
                                    &mut all_reconstructed_shreds,
                                    &mut deshredded_entries,
                                    &send_socket,
                                    &local_dest_sockets,
                                    debug_trace_shred,
                                    &metrics,
                                );

                                // If the channel is closed or error, break out
                                if res.is_err() {
                                    break;
                                }
                            }

                            // refresh thread-local subscribers
                            recv(refresh_subscribers_tick) -> _ => {
                                local_dest_sockets = unioned_dest_sockets.load();
                            }

                            // handle shutdown (avoid using sleep since it can hang)
                            recv(shutdown_receiver) -> _ => {
                                break;
                            }
                        }
                    }
                    info!("Exiting forwarder thread {thread_id}.");
                })
                .unwrap();

            vec![listen_thread, send_thread]
        })
        .collect::<Vec<JoinHandle<()>>>()
}

/// Broadcasts the same packet to multiple recipients, parses it into a Shred if possible,
/// and stores that shred in `all_reconstructed_shreds`.
fn recv_from_channel_and_send_multiple_dest(
    maybe_packet_batch: Result<PacketBatch, RecvError>,
    deduper: &RwLock<Deduper<2, [u8]>>,
    all_reconstructed_shreds: &mut HashMap<Slot, HashMap<u32 /* fec_set_index */, HashSet<Shred>>>,
    deshredded_entries: &mut Vec<Entry>,
    send_socket: &UdpSocket,
    local_dest_sockets: &[SocketAddr],
    debug_trace_shred: bool,
    metrics: &ShredMetrics,
) -> Result<(), ShredstreamProxyError> {
    let packet_batch = maybe_packet_batch.map_err(ShredstreamProxyError::RecvError)?;
    let trace_shred_received_time = SystemTime::now();
    metrics
        .agg_received
        .fetch_add(packet_batch.len() as u64, Ordering::Relaxed);
    debug!(
        "Got batch of {} packets, total size in bytes: {}",
        packet_batch.len(),
        packet_batch.iter().map(|x| x.meta().size).sum::<usize>()
    );

    let mut packet_batch_vec = vec![packet_batch];

    let num_deduped = solana_perf::deduper::dedup_packets_and_count_discards(
        &deduper.read().unwrap(),
        &mut packet_batch_vec,
    );

    // Store stats for each Packet
    packet_batch_vec.iter().for_each(|batch| {
        batch.iter().for_each(|packet| {
            metrics
                .packets_received
                .entry(packet.meta().addr)
                .and_modify(|(discarded, not_discarded)| {
                    *discarded += packet.meta().discard() as u64;
                    *not_discarded += (!packet.meta().discard()) as u64;
                })
                .or_insert_with(|| {
                    (
                        packet.meta().discard() as u64,
                        (!packet.meta().discard()) as u64,
                    )
                });
        });
    });

    // send out
    local_dest_sockets.iter().for_each(|outgoing_socketaddr| {
        let packets_with_dest = packet_batch_vec[0]
            .iter()
            .filter_map(|pkt| {
                let data = pkt.data(..)?;
                let addr = outgoing_socketaddr;
                Some((data, addr))
            })
            .collect::<Vec<(&[u8], &SocketAddr)>>();

        match batch_send(send_socket, &packets_with_dest) {
            Ok(_) => {
                metrics
                    .agg_success_forward
                    .fetch_add(packets_with_dest.len() as u64, Ordering::Relaxed);
                metrics.duplicate.fetch_add(num_deduped, Ordering::Relaxed);
            }
            Err(SendPktsError::IoError(err, num_failed)) => {
                metrics
                    .agg_fail_forward
                    .fetch_add(packets_with_dest.len() as u64, Ordering::Relaxed);
                metrics
                    .duplicate
                    .fetch_add(num_failed as u64, Ordering::Relaxed);
                error!(
                    "Failed to send batch of size {} to {outgoing_socketaddr:?}. \
                     {num_failed} packets failed. Error: {err}",
                    packets_with_dest.len()
                );
            }
        }
    });

    reconstruct_shreds(
        &mut packet_batch_vec,
        all_reconstructed_shreds,
        deshredded_entries,
    );

    // For debugging the special "TraceShred" format
    if debug_trace_shred {
        packet_batch_vec[0]
            .iter()
            .filter_map(|p| TraceShred::decode(p.data(..)?).ok())
            .filter(|t| t.created_at.is_some())
            .for_each(|trace_shred| {
                let elapsed = trace_shred_received_time
                    .duration_since(SystemTime::try_from(trace_shred.created_at.unwrap()).unwrap())
                    .unwrap_or_default();

                datapoint_info!(
                    "shredstream_proxy-trace_shred_latency",
                    "trace_region" => trace_shred.region,
                    ("trace_seq_num", trace_shred.seq_num as i64, i64),
                    ("elapsed_micros", elapsed.as_micros(), i64),
                );
            });
    }

    Ok(())
}

/// Returns the number of shreds reconstructed
/// Updates all_reconstructed_shreds with current state, and deshredded_entries with return values
fn reconstruct_shreds(
    packet_batch_vec: &[PacketBatch],
    all_reconstructed_shreds: &mut HashMap<Slot, HashMap<u32, HashSet<Shred>>>,
    deshredded_entries: &mut Vec<Entry>,
) -> usize {
    deshredded_entries.clear();
    let mut slot_fec_index_to_iterate = HashSet::new();
    for packet in &packet_batch_vec[0] {
        let Some(data) = packet.data(..) else {
            continue;
        };
        match solana_ledger::shred::Shred::new_from_serialized_shred(data.to_vec())
            .and_then(Shred::try_from)
        {
            Ok(shred) => {
                let slot = shred.common_header().slot;
                let fec_set_index = shred.fec_set_index();
                all_reconstructed_shreds
                    .entry(slot)
                    .or_default()
                    .entry(fec_set_index)
                    .or_default()
                    .insert(shred);
                slot_fec_index_to_iterate.insert((slot, fec_set_index));
            }
            Err(e) => {
                warn!("Failed to reconstruct shred. Err: {e:?}");
            }
        }
    }
    let rs_cache = ReedSolomonCache::default();
    let mut recovered_count = 0;
    for (slot, fec_set_index) in slot_fec_index_to_iterate {
        let Some(shreds) = all_reconstructed_shreds
            .get_mut(&slot)
            .and_then(|fec_set_indexes| fec_set_indexes.get_mut(&fec_set_index))
        else {
            continue;
        };

        let (num_expected_shreds, num_data_shreds) = can_recover(shreds);
        println!("expected {num_expected_shreds}"); // TODO: check if sane

        // haven't received last data shred, haven't seen any coding shreds, so wait until more arrive
        if num_expected_shreds == 0
            || (num_data_shreds < num_expected_shreds && shreds.len() < num_data_shreds as usize)
        {
            // not enough data shreds, not enough shreds to recover
            continue;
        }

        if num_data_shreds < num_expected_shreds && shreds.len() as u16 >= num_data_shreds {
            // recover
            let merkle_shreds = shreds.iter().cloned().collect_vec();
            let Ok(recovered) = solana_ledger::shred::merkle::recover(merkle_shreds, &rs_cache)
                .inspect_err(|e| warn!("Failed to recover shreds: {e}"))
            else {
                continue;
            };

            for shred in recovered {
                match shred {
                    Ok(shred) => {
                        recovered_count += 1;
                        shreds.insert(shred);
                    }
                    Err(e) => warn!(
                        "Failed to recover shreds for slot {slot} fec set: {fec_set_index}: {e}"
                    ),
                }
            }
            println!("Recovered {}", recovered_count);
        }

        let sorted_shreds = shreds
            .iter()
            .filter(|s| s.shred_type() == ShredType::Data)
            .sorted_by_key(|s| s.index())
            .collect_vec();

        let sorted_payloads = shreds
            .iter()
            .filter(|s| s.shred_type() == ShredType::Data)
            .inspect(|shred| match &shred {
                Shred::ShredCode(_) => {}
                Shred::ShredData(s) => {
                    if s.data_complete() {
                        println!(
                            "data_complete fec:{}, idx:{}",
                            s.common_header.index, s.common_header.fec_set_index
                        );
                    }
                }
            })
            .sorted_by_key(|s| s.index())
            .map(|s| s.payload().as_ref())
            .collect_vec();
        let a = match &sorted_shreds.last().unwrap() {
            Shred::ShredCode(_) => {
                panic!("fail")
            }
            Shred::ShredData(s) => s.data_complete(),
        };
        if a {
            println!("data complete",);
        }

        let deshred_payload = match Shredder::deshred(sorted_payloads) {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "start idx: {}, end idx: {}. end-start = {}",
                    sorted_shreds.first().unwrap().index(),
                    sorted_shreds.last().as_ref().unwrap().index(),
                    sorted_shreds.last().as_ref().unwrap().index()
                        - sorted_shreds.first().unwrap().index(),
                );
                println!(
                    "slot {slot} failed to deshred fec_set_index {fec_set_index}. num_expected_shreds: {num_expected_shreds}, num_data_shreds: {num_data_shreds}. Err: {e}"
                );
                continue;
            }
        };
        let entries =
            match bincode::deserialize::<Vec<solana_entry::entry::Entry>>(&deshred_payload) {
                Ok(e) => e,
                Err(e) => {
                    println!("slot {slot} failed to deserialize bincode with err: {e}");
                    continue;
                }
            };
        deshredded_entries.extend(entries);
        if let Some(fec_set) = all_reconstructed_shreds.get_mut(&slot) {
            fec_set.remove(&fec_set_index);
            if fec_set.is_empty() {
                all_reconstructed_shreds.remove(&slot);
            }
        }
    }

    recovered_count
}

/// check if we can reconstruct (having minimum number of data + coding shreds)
fn can_recover(
    shreds: &HashSet<Shred>,
) -> (
    u16, /* num_expected_shreds */
    u16, /* num_data_shreds */
) {
    let mut num_expected_shreds = 0;
    let mut data_shred_count = 0;
    for shred in shreds {
        match shred {
            Shred::ShredCode(s) => {
                num_expected_shreds = s.coding_header.num_coding_shreds;
            }
            Shred::ShredData(s) => {
                data_shred_count += 1;
                if s.data_complete() || s.last_in_slot() {
                    num_expected_shreds = shred.index() as u16 + 1;
                }
            }
        }
    }
    (num_expected_shreds, data_shred_count)
}

/// Starts a thread that updates our destinations used by the forwarder threads
pub fn start_destination_refresh_thread(
    endpoint_discovery_url: String,
    discovered_endpoints_port: u16,
    static_dest_sockets: Vec<(SocketAddr, String)>,
    unioned_dest_sockets: Arc<ArcSwap<Vec<SocketAddr>>>,
    shutdown_receiver: Receiver<()>,
    exit: Arc<AtomicBool>,
) -> JoinHandle<()> {
    Builder::new().name("ssPxyDstRefresh".to_string()).spawn(move || {
        let fetch_socket_tick = crossbeam_channel::tick(Duration::from_secs(30));
        let metrics_tick = crossbeam_channel::tick(Duration::from_secs(30));
        let mut socket_count = static_dest_sockets.len();
        while !exit.load(Ordering::Relaxed) {
            crossbeam_channel::select! {
                    recv(fetch_socket_tick) -> _ => {
                        let fetched = fetch_unioned_destinations(
                            &endpoint_discovery_url,
                            discovered_endpoints_port,
                            &static_dest_sockets,
                        );
                        let new_sockets = match fetched {
                            Ok(s) => {
                                info!("Sending shreds to {} destinations: {s:?}", s.len());
                                s
                            }
                            Err(e) => {
                                warn!("Failed to fetch from discovery service, retrying. Error: {e}");
                                datapoint_warn!("shredstream_proxy-destination_refresh_error",
                                                ("prev_unioned_dest_count", socket_count, i64),
                                                ("errors", 1, i64),
                                                ("error_str", e.to_string(), String),
                                );
                                continue;
                            }
                        };
                        socket_count = new_sockets.len();
                        unioned_dest_sockets.store(Arc::new(new_sockets));
                    }
                    recv(metrics_tick) -> _ => {
                        datapoint_info!("shredstream_proxy-destination_refresh_stats",
                                        ("destination_count", socket_count, i64),
                        );
                    }
                    recv(shutdown_receiver) -> _ => {
                        break;
                    }
                }
        }
    }).unwrap()
}

/// Returns dynamically discovered endpoints with CLI arg defined endpoints
fn fetch_unioned_destinations(
    endpoint_discovery_url: &str,
    discovered_endpoints_port: u16,
    static_dest_sockets: &[(SocketAddr, String)],
) -> Result<Vec<SocketAddr>, ShredstreamProxyError> {
    let bytes = reqwest::blocking::get(endpoint_discovery_url)?.bytes()?;

    let sockets_json = match serde_json::from_slice::<Vec<IpAddr>>(&bytes) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "Failed to parse json from: {:?}",
                std::str::from_utf8(&bytes)
            );
            return Err(ShredstreamProxyError::from(e));
        }
    };

    // resolve again since ip address could change
    let static_dest_sockets = static_dest_sockets
        .iter()
        .filter_map(|(_socketaddr, hostname_port)| {
            Some(resolve_hostname_port(hostname_port).ok()?.0)
        })
        .collect::<Vec<_>>();

    let unioned_dest_sockets = sockets_json
        .into_iter()
        .map(|ip| SocketAddr::new(ip, discovered_endpoints_port))
        .chain(static_dest_sockets)
        .unique()
        .collect::<Vec<SocketAddr>>();
    Ok(unioned_dest_sockets)
}

/// Reset dedup + send metrics to influx
pub fn start_forwarder_accessory_thread(
    deduper: Arc<RwLock<Deduper<2, [u8]>>>,
    metrics: Arc<ShredMetrics>,
    metrics_update_interval_ms: u64,
    shutdown_receiver: Receiver<()>,
    exit: Arc<AtomicBool>,
) -> JoinHandle<()> {
    Builder::new()
        .name("ssPxyAccessory".to_string())
        .spawn(move || {
            let metrics_tick =
                crossbeam_channel::tick(Duration::from_millis(metrics_update_interval_ms));
            let deduper_reset_tick = crossbeam_channel::tick(Duration::from_secs(2));
            let mut rng = rand::thread_rng();
            while !exit.load(Ordering::Relaxed) {
                crossbeam_channel::select! {
                    // reset deduper to avoid false positives
                    recv(deduper_reset_tick) -> _ => {
                        deduper
                            .write()
                            .unwrap()
                            .maybe_reset(&mut rng, DEDUPER_FALSE_POSITIVE_RATE, DEDUPER_RESET_CYCLE);
                    }

                    // send metrics to influx
                    recv(metrics_tick) -> _ => {
                        metrics.report();
                        metrics.reset();
                    }

                    // handle SIGINT shutdown
                    recv(shutdown_receiver) -> _ => {
                        break;
                    }
                }
            }
        })
        .unwrap()
}

pub struct ShredMetrics {
    /// Total number of shreds received. Includes duplicates when receiving shreds from multiple regions
    pub agg_received: AtomicU64,
    /// Total number of shreds successfully forwarded, accounting for all destinations
    pub agg_success_forward: AtomicU64,
    /// Total number of shreds failed to forward, accounting for all destinations
    pub agg_fail_forward: AtomicU64,
    /// Number of duplicate shreds received
    pub duplicate: AtomicU64,
    /// (discarded, not discarded, from other shredstream instances)
    pub packets_received: DashMap<IpAddr, (u64, u64)>,

    // cumulative metrics (persist after reset)
    pub agg_received_cumulative: AtomicU64,
    pub agg_success_forward_cumulative: AtomicU64,
    pub agg_fail_forward_cumulative: AtomicU64,
    pub duplicate_cumulative: AtomicU64,
}

impl ShredMetrics {
    pub fn new() -> Self {
        Self {
            agg_received: Default::default(),
            agg_success_forward: Default::default(),
            agg_fail_forward: Default::default(),
            duplicate: Default::default(),
            packets_received: DashMap::with_capacity(10),
            agg_received_cumulative: Default::default(),
            agg_success_forward_cumulative: Default::default(),
            agg_fail_forward_cumulative: Default::default(),
            duplicate_cumulative: Default::default(),
        }
    }

    pub fn report(&self) {
        datapoint_info!(
            "shredstream_proxy-connection_metrics",
            (
                "agg_received",
                self.agg_received.load(Ordering::Relaxed),
                i64
            ),
            (
                "agg_success_forward",
                self.agg_success_forward.load(Ordering::Relaxed),
                i64
            ),
            (
                "agg_fail_forward",
                self.agg_fail_forward.load(Ordering::Relaxed),
                i64
            ),
            ("duplicate", self.duplicate.load(Ordering::Relaxed), i64),
        );
        self.packets_received.iter().for_each(|kv| {
            let (addr, (discarded_packets, not_discarded_packets)) = kv.pair();
            datapoint_info!("shredstream_proxy-receiver_stats",
                "addr" => addr.to_string(),
                ("discarded_packets", *discarded_packets, i64),
                ("not_discarded_packets", *not_discarded_packets, i64),
            );
        });
    }

    /// resets current values, increments cumulative values
    pub fn reset(&self) {
        self.agg_received_cumulative.fetch_add(
            self.agg_received.swap(0, Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.agg_success_forward_cumulative.fetch_add(
            self.agg_success_forward.swap(0, Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.agg_fail_forward_cumulative.fetch_add(
            self.agg_fail_forward.swap(0, Ordering::Relaxed),
            Ordering::Relaxed,
        );
        self.duplicate_cumulative
            .fetch_add(self.duplicate.swap(0, Ordering::Relaxed), Ordering::Relaxed);
        self.packets_received.alter_all(|_ip, _metrics| (0, 0))
    }
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
        str::FromStr,
        sync::{Arc, Mutex, RwLock},
        thread,
        thread::sleep,
        time::Duration,
    };

    use itertools::Itertools;
    use rand::Rng;
    use solana_ledger::{
        blockstore::make_slot_entries_with_transactions,
        shred::{merkle, merkle::Shred, Error, ProcessShredsStats, ReedSolomonCache, Shredder},
    };
    use solana_perf::{
        deduper::Deduper,
        packet::{Meta, Packet, PacketBatch},
    };
    use solana_sdk::{
        clock::Slot,
        hash::Hash,
        packet::{PacketFlags, PACKET_DATA_SIZE},
        signature::Keypair,
    };

    use crate::forwarder::{
        reconstruct_shreds, recv_from_channel_and_send_multiple_dest, ShredMetrics,
    };

    fn listen_and_collect(listen_socket: UdpSocket, received_packets: Arc<Mutex<Vec<Vec<u8>>>>) {
        let mut buf = [0u8; PACKET_DATA_SIZE];
        loop {
            listen_socket.recv(&mut buf).unwrap();
            received_packets.lock().unwrap().push(Vec::from(buf));
        }
    }

    // taken from https://github.com/jito-labs/jito-solana/blob/4326f37332a223ed94f2204308e454b64d9bc852/ledger/src/blockstore.rs#L5414
    // pub fn make_slot_entries_with_transactions(num_entries: u64) -> Vec<Entry> {
    //     let mut entries: Vec<Entry> = Vec::new();
    //     for x in 0..num_entries {
    //         let transaction = Transaction::new_with_compiled_instructions(
    //             &[&Keypair::new()],
    //             &[pubkey::new_rand()],
    //             Hash::default(),
    //             vec![pubkey::new_rand()],
    //             vec![CompiledInstruction::new(1, &(), vec![0])],
    //         );
    //         entries.push(next_entry_mut(&mut Hash::default(), 0, vec![transaction]));
    //         let mut tick = create_ticks(1, 0, hash(&serialize(&x).unwrap()));
    //         entries.append(&mut tick);
    //     }
    //     entries
    // }

    // taken from https://github.com/jito-labs/jito-solana/blob/3d6bbe6838083c087a7663daf1cae46920286cd6/ledger/src/shred.rs#L1034
    pub fn make_merkle_shreds_for_tests<R: Rng>(
        rng: &mut R,
        slot: Slot,
        data_size: usize,
        chained: bool,
        is_last_in_slot: bool,
    ) -> Result<Vec<merkle::Shred>, Error> {
        let thread_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .unwrap();
        let chained_merkle_root = chained.then(|| Hash::new_from_array(rng.gen()));
        let parent_offset = rng.gen_range(1..=u16::try_from(slot).unwrap_or(u16::MAX));
        let parent_slot = slot.checked_sub(u64::from(parent_offset)).unwrap();
        let mut data = vec![0u8; data_size];
        rng.fill(&mut data[..]);
        merkle::make_shreds_from_data(
            &thread_pool,
            &Keypair::new(),
            chained_merkle_root,
            &data[..],
            slot,
            parent_slot,
            rng.gen(),            // shred_version
            rng.gen_range(1..64), // reference_tick
            is_last_in_slot,
            rng.gen_range(0..671), // next_shred_index
            rng.gen_range(0..781), // next_code_index
            &ReedSolomonCache::default(),
            &mut ProcessShredsStats::default(),
        )
    }

    #[test]
    fn test_recover_shreds() {
        test_recover_shreds_runner(true);
        test_recover_shreds_runner(false);
    }

    fn test_recover_shreds_runner(is_last_in_slot: bool) {
        let mut rng = rand::thread_rng();
        let slot = 11_111;
        let leader_keypair = Arc::new(Keypair::new());
        let reed_solomon_cache = ReedSolomonCache::default();
        let shredder = Shredder::new(slot, slot - 1, 0, 0).unwrap();
        let chained_merkle_root = Some(Hash::new_from_array(rng.gen()));
        let num_entry_groups = 10;
        let num_entries = 10;
        let mut entries = Vec::new();
        let mut data_shreds = Vec::new();
        let mut coding_shreds = Vec::new();

        let mut index = 0;
        (0..num_entry_groups).for_each(|_i| {
            let _entries = make_slot_entries_with_transactions(num_entries);
            let (_data_shreds, _coding_shreds) = shredder.entries_to_shreds(
                &leader_keypair,
                _entries.as_slice(),
                true, // is_last_in_slot
                chained_merkle_root,
                index as u32, // next_shred_index
                index as u32, // next_code_index,
                true,         // merkle_variant
                &reed_solomon_cache,
                &mut ProcessShredsStats::default(),
            );
            index += _data_shreds.len();
            entries.extend(_entries);
            data_shreds.extend(_data_shreds);
            coding_shreds.extend(_coding_shreds);
        });

        let packets = data_shreds
            .iter()
            .chain(coding_shreds.iter())
            .map(|s| {
                let mut p = Packet::default();
                s.copy_to_packet(&mut p);
                p
            })
            .collect_vec();
        assert!(data_shreds.len() >= 100);
        assert_eq!(
            data_shreds
                .iter()
                .map(|s| s.fec_set_index())
                .dedup()
                .count(),
            num_entry_groups
        );

        // Test 1: all shreds provided
        let packet_batch = PacketBatch::new(packets.clone());
        let mut deshredded_entries = Vec::new();
        let mut all_reconstructed_shreds: HashMap<
            Slot,
            HashMap<u32 /* fec_set_index */, HashSet<Shred>>,
        > = HashMap::new();
        let recovered_count = reconstruct_shreds(
            [packet_batch.clone()].as_slice(),
            &mut all_reconstructed_shreds,
            &mut deshredded_entries,
        );
        assert_eq!(recovered_count, 0);
        assert_eq!(
            all_reconstructed_shreds.len(),
            0,
            "should remove all FEC blocks due to successful reconstruction"
        );
        assert_eq!(deshredded_entries.len(), entries.len());

        // Test 2: 33% of shreds missing
        let packet_batch = PacketBatch::new(
            packets
                .iter()
                .enumerate()
                .filter(|(i, _)| i % 3 != 0)
                .map(|(_i, packet)| packet)
                .cloned()
                .collect_vec(),
        );
        let mut deshredded_entries = Vec::new();
        let mut all_reconstructed_shreds: HashMap<
            Slot,
            HashMap<u32 /* fec_set_index */, HashSet<Shred>>,
        > = HashMap::new();
        let recovered_count = reconstruct_shreds(
            [packet_batch.clone()].as_slice(),
            &mut all_reconstructed_shreds,
            &mut deshredded_entries,
        );
        assert!(recovered_count > entries.len() / 3);
        assert_eq!(
            all_reconstructed_shreds.len(),
            0,
            "should remove all FEC blocks due to successful reconstruction"
        );
        assert_eq!(deshredded_entries.len(), entries.len());
    }

    #[test]
    fn test_2shreds_3destinations() {
        let packet_batch = PacketBatch::new(vec![
            Packet::new(
                [1; PACKET_DATA_SIZE],
                Meta {
                    size: PACKET_DATA_SIZE,
                    addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    port: 48289, // received on random port
                    flags: PacketFlags::empty(),
                },
            ),
            Packet::new(
                [2; PACKET_DATA_SIZE],
                Meta {
                    size: PACKET_DATA_SIZE,
                    addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                    port: 9999,
                    flags: PacketFlags::empty(),
                },
            ),
        ]);
        let (packet_sender, packet_receiver) = crossbeam_channel::unbounded::<PacketBatch>();
        packet_sender.send(packet_batch).unwrap();

        let dest_socketaddrs = vec![
            SocketAddr::from_str("0.0.0.0:32881").unwrap(),
            SocketAddr::from_str("0.0.0.0:33881").unwrap(),
            SocketAddr::from_str("0.0.0.0:34881").unwrap(),
        ];

        let test_listeners = dest_socketaddrs
            .iter()
            .map(|socketaddr| {
                (
                    UdpSocket::bind(socketaddr).unwrap(),
                    *socketaddr,
                    // store results in vec of packet, where packet is Vec<u8>
                    Arc::new(Mutex::new(vec![])),
                )
            })
            .collect::<Vec<_>>();

        let udp_sender = UdpSocket::bind("0.0.0.0:10000").unwrap();

        // spawn listeners
        test_listeners
            .iter()
            .for_each(|(listen_socket, _socketaddr, to_receive)| {
                let socket = listen_socket.try_clone().unwrap();
                let to_receive = to_receive.to_owned();
                thread::spawn(move || listen_and_collect(socket, to_receive));
            });

        let mut all_reconstructed_shreds: HashMap<
            Slot,
            HashMap<u32 /* fec_set_index */, HashSet<Shred>>,
        > = HashMap::new();
        // send packets
        recv_from_channel_and_send_multiple_dest(
            packet_receiver.recv(),
            &Arc::new(RwLock::new(Deduper::<2, [u8]>::new(
                &mut rand::thread_rng(),
                crate::forwarder::DEDUPER_NUM_BITS,
            ))),
            &mut all_reconstructed_shreds,
            &mut Vec::new(),
            &udp_sender,
            &Arc::new(dest_socketaddrs),
            false,
            &Arc::new(ShredMetrics::new()),
        )
        .unwrap();

        // allow packets to be received
        sleep(Duration::from_millis(500));

        let received = test_listeners
            .iter()
            .map(|(_, _, results)| results.clone())
            .collect::<Vec<_>>();

        // check results
        for received in received.iter() {
            let received = received.lock().unwrap();
            assert_eq!(received.len(), 2);
            assert!(received
                .iter()
                .all(|packet| packet.len() == PACKET_DATA_SIZE));
            assert_eq!(received[0], [1; PACKET_DATA_SIZE]);
            assert_eq!(received[1], [2; PACKET_DATA_SIZE]);
        }

        assert_eq!(
            received
                .iter()
                .fold(0, |acc, elem| acc + elem.lock().unwrap().len()),
            6
        );
    }
}
