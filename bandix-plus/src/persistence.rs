use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::monitor::{AggregatedBucket, HistogramHistory, MonitorRuntime, MonitorRuntimeState, export_runtime_state, import_runtime_state};
use crate::topology::TopologySnapshot;
use crate::utils::time_utils;

const DEVICES_SCHEMA_VERSION: u32 = 1;
const CURRENT_HOUR_SCHEMA_VERSION: u32 = 2;

const RING_MAGIC: [u8; 8] = *b"BDXPRNG1";
const RING_VERSION: u32 = 2;
const RING_V1_RECORD_SIZE: usize = 22 * 8 + 4;
#[cfg(test)]
const RING_SLOT_COUNT: u32 = 30 * 24;
const RING_HEADER_SIZE: usize = 64;
const RING_RECORD_DATA_SIZE: usize = 27 * 8;
const RING_RECORD_SIZE: usize = RING_RECORD_DATA_SIZE + 4;

#[derive(Debug, Clone)]
pub struct PersistenceManager {
    ring_slots: u32,
    data_dir: PathBuf,
    devices_path: PathBuf,
    current_hour_path: PathBuf,
    iface_traffic_dir: PathBuf,
    device_traffic_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedDevicesFile {
    schema_version: u32,
    state: MonitorRuntimeState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedCurrentHourFile {
    schema_version: u32,
    state: PersistedCurrentHourState,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PersistedCurrentHourState {
    iface: Vec<PersistedCurrentHourIface>,
    device: Vec<PersistedCurrentHourDevice>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedCurrentHourIface {
    logical_iface: String,
    bucket: AggregatedBucket,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedCurrentHourDevice {
    logical_iface: String,
    mac: String,
    bucket: AggregatedBucket,
}

#[derive(Debug, Clone, Copy)]
struct RingHeader {
    version: u32,
    slot_count: u32,
    write_pos: u32,
    valid_count: u32,
    record_size: u32,
}

#[derive(Debug, Clone)]
struct RingRecord {
    bucket: AggregatedBucket,
}

impl PersistenceManager {
    pub fn new(data_dir: impl AsRef<Path>, ring_days: u32) -> anyhow::Result<Self> {
        anyhow::ensure!((1..=90).contains(&ring_days), "--ring-buffer must be between 1 and 90 days");
        let ring_slots = ring_days * 24;
        let data_dir = data_dir.as_ref().to_path_buf();
        let iface_traffic_dir = data_dir.join("traffic").join("iface");
        let device_traffic_dir = data_dir.join("traffic").join("device");
        fs::create_dir_all(&iface_traffic_dir)?;
        fs::create_dir_all(&device_traffic_dir)?;
        Ok(Self {
            ring_slots,
            devices_path: data_dir.join("devices_state.json"),
            current_hour_path: data_dir.join("current_hour_state.json"),
            data_dir,
            iface_traffic_dir,
            device_traffic_dir,
        })
    }

    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    pub fn save_monitor_runtime(&self, runtime: &MonitorRuntime, topology: &TopologySnapshot) -> anyhow::Result<()> {
        let data = PersistedDevicesFile {
            schema_version: DEVICES_SCHEMA_VERSION,
            state: export_runtime_state(runtime, topology),
        };
        write_json_atomic(&self.devices_path, &data)
    }

    pub fn load_monitor_runtime(&self, runtime: &mut MonitorRuntime, topology: &TopologySnapshot) -> anyhow::Result<()> {
        let Some(data) = read_json_or_quarantine::<PersistedDevicesFile>(&self.devices_path)? else {
            return Ok(());
        };
        if data.schema_version != DEVICES_SCHEMA_VERSION {
            anyhow::bail!(
                "unsupported devices schema version {} in {}",
                data.schema_version,
                self.devices_path.display()
            );
        }
        import_runtime_state(runtime, data.state, topology)
    }

    pub fn save_current_hour_histogram(&self, histogram: &HistogramHistory, topology: &TopologySnapshot) -> anyhow::Result<()> {
        let exported = histogram.export_current_hour_state();
        let mut iface = Vec::new();
        for item in exported.iface {
            let Some(info) = topology.by_ifindex(item.ifindex) else {
                continue;
            };
            iface.push(PersistedCurrentHourIface {
                logical_iface: info.name.clone(),
                bucket: item.bucket,
            });
        }
        let mut device = Vec::new();
        for item in exported.device {
            let Some(info) = topology.by_ifindex(item.ifindex) else {
                continue;
            };
            device.push(PersistedCurrentHourDevice {
                logical_iface: info.name.clone(),
                mac: item.mac,
                bucket: item.bucket,
            });
        }
        let data = PersistedCurrentHourFile {
            schema_version: CURRENT_HOUR_SCHEMA_VERSION,
            state: PersistedCurrentHourState { iface, device },
        };
        write_json_atomic(&self.current_hour_path, &data)
    }

    pub fn load_current_hour_histogram(
        &self,
        topology: &TopologySnapshot,
        histogram: &mut HistogramHistory,
        now_ms: u64,
    ) -> anyhow::Result<()> {
        let Some(data) = read_json_or_quarantine::<PersistedCurrentHourFile>(&self.current_hour_path)? else {
            return Ok(());
        };
        if data.schema_version != CURRENT_HOUR_SCHEMA_VERSION {
            log::info!(
                "current-hour schema version {} != {}, discarding persisted state",
                data.schema_version,
                CURRENT_HOUR_SCHEMA_VERSION
            );
            return Ok(());
        }

        let (current_start, _current_end) = crate::monitor::hourly_bucket_local(now_ms);

        for item in data.state.iface {
            if item.bucket.start_ts_ms != current_start {
                log::debug!(
                    "discarding stale iface bucket for {} (bucket hour {} != current {})",
                    item.logical_iface,
                    item.bucket.start_ts_ms,
                    current_start
                );
                continue;
            }
            let Some(ifindex) = topology.ifindex_by_name(&item.logical_iface) else {
                continue;
            };
            histogram.current_hour_iface.insert(ifindex, item.bucket);
        }

        for item in data.state.device {
            if item.bucket.start_ts_ms != current_start {
                continue;
            }
            let Some(ifindex) = topology.ifindex_by_name(&item.logical_iface) else {
                continue;
            };
            histogram
                .current_hour_device
                .insert(crate::monitor::DeviceSeriesKey { ifindex, mac: item.mac }, item.bucket);
        }
        Ok(())
    }

    pub fn append_iface_bucket(&self, iface_name: &str, bucket: &AggregatedBucket) -> anyhow::Result<()> {
        let path = self.iface_traffic_dir.join(format!("{}.ring", encode_component(iface_name)));
        append_ring_record_with_capacity(&path, &RingRecord { bucket: bucket.clone() }, self.ring_slots)
    }

    pub fn append_device_bucket(&self, iface_name: &str, mac: &str, bucket: &AggregatedBucket) -> anyhow::Result<()> {
        let mac_hex = normalize_mac_hex(mac).ok_or_else(|| anyhow::anyhow!("invalid mac for ring path: {}", mac))?;
        let path = self
            .device_traffic_dir
            .join(format!("{}-{}.ring", encode_component(iface_name), mac_hex));
        append_ring_record_with_capacity(&path, &RingRecord { bucket: bucket.clone() }, self.ring_slots)
    }

    /// Delete the completed histogram ring belonging to one device.
    pub fn delete_device_traffic(&self, iface_name: &str, mac: &str) -> anyhow::Result<bool> {
        let mac_hex = normalize_mac_hex(mac).ok_or_else(|| anyhow::anyhow!("invalid mac for ring path: {}", mac))?;
        let path = self
            .device_traffic_dir
            .join(format!("{}-{}.ring", encode_component(iface_name), mac_hex));
        if !path.exists() {
            return Ok(false);
        }
        fs::remove_file(path)?;
        Ok(true)
    }

    pub fn load_histogram(&self, topology: &TopologySnapshot, histogram: &mut HistogramHistory) -> anyhow::Result<()> {
        self.load_iface_histogram(topology, histogram)?;
        self.load_device_histogram(topology, histogram)?;
        Ok(())
    }

    fn load_iface_histogram(&self, topology: &TopologySnapshot, histogram: &mut HistogramHistory) -> anyhow::Result<()> {
        if !self.iface_traffic_dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(&self.iface_traffic_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !is_ring_file(&path) {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|x| x.to_str()) else {
                continue;
            };
            let Some(iface_name) = decode_component(stem) else {
                quarantine_bad_file(&path)?;
                continue;
            };
            let Some(ifindex) = topology.ifindex_by_name(&iface_name) else {
                continue;
            };
            // Resize once on recovery, including rings of offline devices.
            drop(open_or_create_ring(&path, self.ring_slots)?);
            let records = read_ring_records(&path)?;
            for r in records {
                histogram.restore_iface_bucket(ifindex, r.bucket);
            }
        }
        Ok(())
    }

    fn load_device_histogram(&self, topology: &TopologySnapshot, histogram: &mut HistogramHistory) -> anyhow::Result<()> {
        if !self.device_traffic_dir.exists() {
            return Ok(());
        }
        for entry in fs::read_dir(&self.device_traffic_dir)? {
            let entry = entry?;
            let path = entry.path();
            if !is_ring_file(&path) {
                continue;
            }
            let Some(stem) = path.file_stem().and_then(|x| x.to_str()) else {
                continue;
            };
            let Some((iface_hex, mac_hex)) = stem.rsplit_once('-') else {
                quarantine_bad_file(&path)?;
                continue;
            };
            let Some(iface_name) = decode_component(iface_hex) else {
                quarantine_bad_file(&path)?;
                continue;
            };
            let Some(ifindex) = topology.ifindex_by_name(&iface_name) else {
                continue;
            };
            let Some(mac) = mac_hex_to_colon(mac_hex) else {
                quarantine_bad_file(&path)?;
                continue;
            };
            // Resize once on recovery, including rings of offline devices.
            drop(open_or_create_ring(&path, self.ring_slots)?);
            let records = read_ring_records(&path)?;
            for r in records {
                histogram.restore_device_bucket(ifindex, mac.clone(), r.bucket);
            }
        }
        Ok(())
    }
}

fn write_json_atomic<T: Serialize>(path: &Path, data: &T) -> anyhow::Result<()> {
    let Some(parent) = path.parent() else {
        anyhow::bail!("invalid path without parent: {}", path.display());
    };
    fs::create_dir_all(parent)?;

    let tmp = path.with_extension(format!("tmp.{}", time_utils::now_millis()));
    let payload = serde_json::to_vec(data)?;

    {
        let mut f = File::create(&tmp)?;
        f.write_all(&payload)?;
        f.sync_all()?;
    }

    fs::rename(&tmp, path)?;
    Ok(())
}

fn read_json_or_quarantine<T: DeserializeOwned>(path: &Path) -> anyhow::Result<Option<T>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = match fs::read(path) {
        Ok(v) => v,
        Err(e) => {
            quarantine_bad_file(path)?;
            anyhow::bail!("failed to read {}: {}", path.display(), e);
        }
    };
    let parsed = serde_json::from_slice::<T>(&bytes);
    match parsed {
        Ok(v) => Ok(Some(v)),
        Err(_) => {
            quarantine_bad_file(path)?;
            Ok(None)
        }
    }
}

#[cfg(test)]
fn append_ring_record(path: &Path, record: &RingRecord) -> anyhow::Result<()> {
    append_ring_record_with_capacity(path, record, RING_SLOT_COUNT)
}

fn append_ring_record_with_capacity(path: &Path, record: &RingRecord, slot_count: u32) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = open_or_create_ring(path, slot_count)?;
    let mut header = read_ring_header(&mut file)?;
    let slot = (header.write_pos % header.slot_count) as usize;

    let record_offset = ring_data_offset(&header, slot as u32);
    file.seek(SeekFrom::Start(record_offset))?;
    let encoded = encode_ring_record(record)?;
    file.write_all(&encoded)?;

    header.write_pos = (slot as u32 + 1) % header.slot_count;
    header.valid_count = (header.valid_count + 1).min(header.slot_count);

    write_ring_header(&mut file, &header)?;
    file.sync_data()?;
    Ok(())
}

fn read_ring_records(path: &Path) -> anyhow::Result<Vec<RingRecord>> {
    read_ring_records_limited(path, u32::MAX)
}

fn read_ring_records_limited(path: &Path, limit: u32) -> anyhow::Result<Vec<RingRecord>> {
    // An I/O failure is not evidence of corruption; leave the source intact.
    let mut file = OpenOptions::new().read(true).open(path)?;
    let header = match read_ring_header(&mut file) {
        Ok(h) => h,
        Err(_) => {
            quarantine_bad_file(path)?;
            return Ok(Vec::new());
        }
    };
    let file_len = file.metadata()?.len();
    let (min_expected, max_expected) = match ring_size_bounds(&header) {
        Ok(v) => v,
        Err(_) => {
            quarantine_bad_file(path)?;
            return Ok(Vec::new());
        }
    };
    if file_len < min_expected || file_len > max_expected {
        quarantine_bad_file(path)?;
        return Ok(Vec::new());
    }

    let count = header.valid_count.min(limit);
    let mut out = Vec::with_capacity(count as usize);
    let start_idx = (header.write_pos as u64 + header.slot_count as u64 - count as u64) % header.slot_count as u64;
    let mut buf = vec![0u8; header.record_size as usize];
    let mut reader = std::io::BufReader::new(file);
    reader.seek(SeekFrom::Start(ring_data_offset(&header, start_idx as u32)))?;
    for i in 0..count {
        let idx = ((start_idx + i as u64) % header.slot_count as u64) as u32;
        let offset = ring_data_offset(&header, idx);
        let end = offset.saturating_add(header.record_size as u64);
        if end > file_len {
            quarantine_bad_file(path)?;
            return Ok(Vec::new());
        }
        if i > 0 && idx == 0 {
            reader.seek(SeekFrom::Start(offset))?;
        }
        reader.read_exact(&mut buf)?;
        let record = match decode_ring_record(&buf, header.version) {
            Ok(r) => r,
            Err(_) => {
                quarantine_bad_file(path)?;
                return Ok(Vec::new());
            }
        };
        out.push(record);
    }
    Ok(out)
}

fn open_or_create_ring(path: &Path, slot_count: u32) -> anyhow::Result<File> {
    anyhow::ensure!(slot_count > 0, "ring capacity must be positive");
    if !path.exists() {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        let header = default_ring_header(slot_count);
        write_ring_header(&mut f, &header)?;
        return Ok(f);
    }

    let mut f = OpenOptions::new().read(true).write(true).open(path)?;
    let header = match read_ring_header(&mut f) {
        Ok(v) => v,
        Err(_) => {
            quarantine_bad_file(path)?;
            return open_or_create_ring(path, slot_count);
        }
    };
    let (min_expected, max_expected) = ring_size_bounds(&header)?;
    let actual = f.metadata()?.len();
    if actual < min_expected || actual > max_expected {
        quarantine_bad_file(path)?;
        return open_or_create_ring(path, slot_count);
    }
    if header.version == 1 || header.slot_count != slot_count {
        // Decode before replacing anything. Write the converted ring beside
        // the original and rename atomically so interrupted migration cannot
        // destroy valid history. Shrinking retains the newest records.
        let records = read_ring_records_limited(path, slot_count)?;
        let tmp = path.with_extension(format!("migrate.{}.{}", std::process::id(), time_utils::now_millis()));
        let migration = (|| -> anyhow::Result<()> {
            let mut converted = OpenOptions::new().write(true).create_new(true).open(&tmp)?;
            let new_header = RingHeader {
                slot_count,
                valid_count: records.len() as u32,
                write_pos: records.len() as u32 % slot_count,
                ..default_ring_header(slot_count)
            };
            write_ring_header(&mut converted, &new_header)?;
            for record in &records {
                converted.write_all(&encode_ring_record(record)?)?;
            }
            converted.sync_all()?;
            fs::rename(&tmp, path)?;
            Ok(())
        })();
        if migration.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        migration?;
        return Ok(OpenOptions::new().read(true).write(true).open(path)?);
    }
    Ok(f)
}

fn default_ring_header(slot_count: u32) -> RingHeader {
    RingHeader {
        version: RING_VERSION,
        slot_count,
        write_pos: 0,
        valid_count: 0,
        record_size: RING_RECORD_SIZE as u32,
    }
}

fn ring_total_size(header: &RingHeader) -> usize {
    RING_HEADER_SIZE + header.slot_count as usize * header.record_size as usize
}

fn ring_min_size(header: &RingHeader) -> anyhow::Result<usize> {
    let prefix = RING_HEADER_SIZE;
    if header.valid_count == 0 {
        return Ok(prefix);
    }
    if header.valid_count < header.slot_count {
        if header.write_pos != header.valid_count {
            anyhow::bail!(
                "invalid ring header for non-full ring write_pos={} valid_count={}",
                header.write_pos,
                header.valid_count
            );
        }
        return Ok(prefix + header.valid_count as usize * header.record_size as usize);
    }
    Ok(prefix + header.slot_count as usize * header.record_size as usize)
}

fn ring_size_bounds(header: &RingHeader) -> anyhow::Result<(u64, u64)> {
    let min = ring_min_size(header)? as u64;
    let max = ring_total_size(header) as u64;
    Ok((min, max))
}

fn ring_data_offset(header: &RingHeader, slot_idx: u32) -> u64 {
    RING_HEADER_SIZE as u64 + slot_idx as u64 * header.record_size as u64
}

fn write_ring_header(file: &mut File, header: &RingHeader) -> anyhow::Result<()> {
    let mut buf = vec![0u8; RING_HEADER_SIZE];
    buf[0..8].copy_from_slice(&RING_MAGIC);
    buf[8..12].copy_from_slice(&header.version.to_le_bytes());
    buf[12..16].copy_from_slice(&header.slot_count.to_le_bytes());
    buf[16..20].copy_from_slice(&header.write_pos.to_le_bytes());
    buf[20..24].copy_from_slice(&header.valid_count.to_le_bytes());
    buf[24..28].copy_from_slice(&header.record_size.to_le_bytes());
    let sum = checksum32(&buf[0..28]);
    buf[28..32].copy_from_slice(&sum.to_le_bytes());

    file.seek(SeekFrom::Start(0))?;
    file.write_all(&buf)?;
    Ok(())
}

fn read_ring_header(file: &mut File) -> anyhow::Result<RingHeader> {
    let mut buf = vec![0u8; RING_HEADER_SIZE];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut buf)?;

    if buf[0..8] != RING_MAGIC {
        anyhow::bail!("invalid ring magic");
    }
    let version = u32::from_le_bytes(buf[8..12].try_into().unwrap());
    if version != 1 && version != RING_VERSION {
        anyhow::bail!("unsupported ring version {}", version);
    }
    let checksum = u32::from_le_bytes(buf[28..32].try_into().unwrap());
    let expected = checksum32(&buf[0..28]);
    if checksum != expected {
        anyhow::bail!("invalid ring header checksum");
    }

    let slot_count = u32::from_le_bytes(buf[12..16].try_into().unwrap());
    let write_pos = u32::from_le_bytes(buf[16..20].try_into().unwrap());
    let valid_count = u32::from_le_bytes(buf[20..24].try_into().unwrap());
    let record_size = u32::from_le_bytes(buf[24..28].try_into().unwrap());

    let expected_record_size = if version == 1 { RING_V1_RECORD_SIZE } else { RING_RECORD_SIZE };
    if slot_count == 0 || record_size as usize != expected_record_size {
        anyhow::bail!("invalid ring header values");
    }
    if write_pos >= slot_count || valid_count > slot_count {
        anyhow::bail!("invalid ring positions");
    }

    Ok(RingHeader {
        version,
        slot_count,
        write_pos,
        valid_count,
        record_size,
    })
}

fn encode_ring_record(record: &RingRecord) -> anyhow::Result<Vec<u8>> {
    let b = &record.bucket;
    let mut data = Vec::with_capacity(RING_RECORD_DATA_SIZE);
    for v in [
        b.start_ts_ms,
        b.end_ts_ms,
        b.sample_count,
        b.up_v4_bytes,
        b.down_v4_bytes,
        b.up_v6_bytes,
        b.down_v6_bytes,
        b.up_v4_bps_sum,
        b.up_v4_bps_max,
        b.up_v4_bps_min,
        b.up_v4_bps_avg,
        b.up_v4_bps_p95,
        b.down_v4_bps_sum,
        b.down_v4_bps_max,
        b.down_v4_bps_min,
        b.down_v4_bps_avg,
        b.down_v4_bps_p95,
        b.up_v6_bps_sum,
        b.up_v6_bps_max,
        b.up_v6_bps_min,
        b.up_v6_bps_avg,
        b.up_v6_bps_p95,
        b.down_v6_bps_sum,
        b.down_v6_bps_max,
        b.down_v6_bps_min,
        b.down_v6_bps_avg,
        b.down_v6_bps_p95,
    ] {
        data.extend_from_slice(&v.to_le_bytes());
    }
    if data.len() != RING_RECORD_DATA_SIZE {
        anyhow::bail!("unexpected ring record size");
    }
    let checksum = checksum32(&data);
    data.extend_from_slice(&checksum.to_le_bytes());
    Ok(data)
}

fn decode_ring_record(data: &[u8], version: u32) -> anyhow::Result<RingRecord> {
    let record_size = if version == 1 { RING_V1_RECORD_SIZE } else { RING_RECORD_SIZE };
    if data.len() != record_size {
        anyhow::bail!("invalid ring record length");
    }
    let data_size = record_size - 4;
    let checksum = u32::from_le_bytes(data[data_size..].try_into().unwrap());
    let expected = checksum32(&data[..data_size]);
    if checksum != expected {
        anyhow::bail!("ring record checksum mismatch");
    }

    let mut offset = 0usize;
    let mut next = || {
        let v = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;
        v
    };

    if version == 1 {
        let mut bucket = AggregatedBucket {
            start_ts_ms: next(),
            end_ts_ms: next(),
            up_v4_bytes: next(),
            down_v4_bytes: next(),
            up_v6_bytes: next(),
            down_v6_bytes: next(),
            up_v4_bps_avg: next(),
            up_v4_bps_max: next(),
            up_v4_bps_min: next(),
            up_v4_bps_p95: next(),
            down_v4_bps_avg: next(),
            down_v4_bps_max: next(),
            down_v4_bps_min: next(),
            down_v4_bps_p95: next(),
            up_v6_bps_avg: next(),
            up_v6_bps_max: next(),
            up_v6_bps_min: next(),
            up_v6_bps_p95: next(),
            down_v6_bps_avg: next(),
            down_v6_bps_max: next(),
            down_v6_bps_min: next(),
            down_v6_bps_p95: next(),
            ..Default::default()
        };

        // Version 1 stored averages but no sample counts or rate sums. Preserve
        // each legacy hour as one aggregate observation; exact sample weights
        // cannot be recovered from this format. Byte totals remain exact.
        bucket.sample_count = 1;
        bucket.up_v4_bps_sum = bucket.up_v4_bps_avg;
        bucket.down_v4_bps_sum = bucket.down_v4_bps_avg;
        bucket.up_v6_bps_sum = bucket.up_v6_bps_avg;
        bucket.down_v6_bps_sum = bucket.down_v6_bps_avg;
        return Ok(RingRecord { bucket });
    }

    let bucket = AggregatedBucket {
        start_ts_ms: next(),
        end_ts_ms: next(),
        sample_count: next(),
        up_v4_bytes: next(),
        down_v4_bytes: next(),
        up_v6_bytes: next(),
        down_v6_bytes: next(),
        up_v4_bps_sum: next(),
        up_v4_bps_max: next(),
        up_v4_bps_min: next(),
        up_v4_bps_avg: next(),
        up_v4_bps_p95: next(),
        down_v4_bps_sum: next(),
        down_v4_bps_max: next(),
        down_v4_bps_min: next(),
        down_v4_bps_avg: next(),
        down_v4_bps_p95: next(),
        up_v6_bps_sum: next(),
        up_v6_bps_max: next(),
        up_v6_bps_min: next(),
        up_v6_bps_avg: next(),
        up_v6_bps_p95: next(),
        down_v6_bps_sum: next(),
        down_v6_bps_max: next(),
        down_v6_bps_min: next(),
        down_v6_bps_avg: next(),
        down_v6_bps_p95: next(),
    };

    Ok(RingRecord { bucket })
}

fn checksum32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c9dc5;
    for b in data {
        hash ^= *b as u32;
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn is_ring_file(path: &Path) -> bool {
    path.extension().and_then(|x| x.to_str()) == Some("ring")
}

fn normalize_mac_hex(mac: &str) -> Option<String> {
    let compact: String = mac.chars().filter(|c| *c != ':').collect::<String>().to_ascii_lowercase();
    if compact.len() != 12 || !compact.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    Some(compact)
}

fn mac_hex_to_colon(hex: &str) -> Option<String> {
    if hex.len() != 12 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let mut parts = Vec::with_capacity(6);
    for i in 0..6 {
        parts.push(hex[i * 2..i * 2 + 2].to_ascii_lowercase());
    }
    Some(parts.join(":"))
}

fn encode_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 2);
    for b in input.as_bytes() {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn decode_component(hex: &str) -> Option<String> {
    if hex.is_empty() || hex.len() % 2 != 0 {
        return None;
    }
    let mut bytes = Vec::with_capacity(hex.len() / 2);
    let chars: Vec<char> = hex.chars().collect();
    for i in (0..chars.len()).step_by(2) {
        let hi = chars[i];
        let lo = chars[i + 1];
        let s = [hi, lo].iter().collect::<String>();
        let v = u8::from_str_radix(&s, 16).ok()?;
        bytes.push(v);
    }
    String::from_utf8(bytes).ok()
}

fn quarantine_bad_file(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow::anyhow!("invalid filename for {}", path.display()))?;
    let bad_name = format!("{}.bad.{}", file_name, time_utils::now_millis());
    let bad_path = path.with_file_name(bad_name);
    fs::rename(path, bad_path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // The v1 wire layout: timestamps, four byte totals, then avg/max/min/p95
    // for each direction. Keep this fixture independent of the v2 encoder.
    fn write_v1_ring(path: &Path, slots: u32, write_pos: u32, starts: &[u64], preallocate: bool) {
        let mut file = File::create(path).unwrap();
        let header = RingHeader {
            version: 1,
            slot_count: slots,
            write_pos,
            valid_count: starts.len() as u32,
            record_size: RING_V1_RECORD_SIZE as u32,
        };
        write_ring_header(&mut file, &header).unwrap();
        for start in starts {
            let mut bytes = Vec::new();
            for value in [
                *start,
                *start + 3_599_999,
                1,
                2,
                3,
                4,
                5,
                6,
                7,
                8,
                9,
                10,
                11,
                12,
                13,
                14,
                15,
                16,
                17,
                18,
                19,
                20,
            ] {
                bytes.extend_from_slice(&value.to_le_bytes());
            }
            bytes.extend_from_slice(&checksum32(&bytes).to_le_bytes());
            file.write_all(&bytes).unwrap();
        }
        if preallocate {
            file.set_len(ring_total_size(&header) as u64).unwrap();
        }
    }

    #[test]
    fn ring_resize_preserves_recent_records_and_grows_on_demand() {
        let dir = std::env::temp_dir().join(format!("bandix-plus-resize-{}", time_utils::now_millis()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("x.ring");
        for start in 0..7 {
            append_ring_record_with_capacity(
                &path,
                &RingRecord {
                    bucket: sample_bucket(start),
                },
                4,
            )
            .unwrap();
        }
        drop(open_or_create_ring(&path, 2).unwrap());
        let starts = |path: &Path| {
            read_ring_records(path)
                .unwrap()
                .iter()
                .map(|r| r.bucket.start_ts_ms)
                .collect::<Vec<_>>()
        };
        assert_eq!(starts(&path), vec![5, 6]);
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            (RING_HEADER_SIZE + 2 * RING_RECORD_SIZE) as u64
        );
        drop(open_or_create_ring(&path, 8).unwrap());
        assert_eq!(starts(&path), vec![5, 6]);
        assert_eq!(
            fs::metadata(&path).unwrap().len(),
            (RING_HEADER_SIZE + 2 * RING_RECORD_SIZE) as u64
        );
        append_ring_record_with_capacity(&path, &RingRecord { bucket: sample_bucket(7) }, 8).unwrap();
        assert_eq!(starts(&path), vec![5, 6, 7]);
        let manager = PersistenceManager::new(dir.join("manager"), 2).unwrap();
        manager.append_iface_bucket("br-lan", &sample_bucket(0)).unwrap();
        manager
            .append_device_bucket("br-lan", "02:00:00:00:00:01", &sample_bucket(0))
            .unwrap();
        for directory in [&manager.iface_traffic_dir, &manager.device_traffic_dir] {
            let file = fs::read_dir(directory).unwrap().next().unwrap().unwrap().path();
            assert_eq!(read_ring_header(&mut File::open(file).unwrap()).unwrap().slot_count, 48);
        }
        assert!(PersistenceManager::new(dir.join("invalid"), 0).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn legacy_rings_read_and_migrate_without_losing_history() {
        let dir = std::env::temp_dir().join(format!("bandix-plus-v1-{}", time_utils::now_millis()));
        fs::create_dir_all(&dir).unwrap();
        for (name, starts, write_pos, preallocate, expected) in [
            ("partial", vec![10, 20], 2, false, vec![10, 20, 40]),
            ("preallocated", vec![10, 20], 2, true, vec![10, 20, 40]),
            ("wrapped", vec![30, 10, 20], 1, false, vec![20, 30, 40]),
            ("empty", vec![], 0, false, vec![40]),
        ] {
            let path = dir.join(format!("{name}.ring"));
            write_v1_ring(&path, 3, write_pos, &starts, preallocate);
            let before = read_ring_records(&path).unwrap();
            for record in &before {
                assert_eq!(record.bucket.up_v4_bytes, 1);
                assert_eq!(record.bucket.down_v4_bytes, 2);
                assert_eq!(record.bucket.up_v6_bytes, 3);
                assert_eq!(record.bucket.down_v6_bytes, 4);
                assert_eq!(record.bucket.up_v4_bps_avg, 5);
                assert_eq!(record.bucket.down_v4_bps_avg, 9);
                assert_eq!(record.bucket.up_v6_bps_avg, 13);
                assert_eq!(record.bucket.down_v6_bps_avg, 17);
                assert_eq!(record.bucket.clone().finalize().up_v4_bps_avg, 5);
            }
            let mut histogram = HistogramHistory::with_capacity_hours(30 * 24);
            for record in &before {
                histogram.restore_iface_bucket(1, record.bucket.clone());
            }
            if !before.is_empty() {
                assert_eq!(
                    histogram.cumulative_from_completed().0[&1].down_v6_bytes,
                    4 * before.len() as u64
                );
            }
            append_ring_record_with_capacity(&path, &RingRecord { bucket: sample_bucket(40) }, 3).unwrap();
            let after = read_ring_records(&path).unwrap();
            assert_eq!(after.iter().map(|r| r.bucket.start_ts_ms).collect::<Vec<_>>(), expected);
            for record in after.iter().filter(|r| r.bucket.start_ts_ms != 40) {
                let original = before
                    .iter()
                    .find(|r| r.bucket.start_ts_ms == record.bucket.start_ts_ms)
                    .unwrap();
                assert_eq!(
                    serde_json::to_value(&record.bucket).unwrap(),
                    serde_json::to_value(&original.bucket).unwrap()
                );
            }
            assert_eq!(read_ring_header(&mut File::open(&path).unwrap()).unwrap().version, RING_VERSION);
        }
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 4);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn corrupt_legacy_record_is_still_quarantined() {
        let dir = std::env::temp_dir().join(format!("bandix-plus-v1-corrupt-{}", time_utils::now_millis()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.ring");
        write_v1_ring(&path, 3, 1, &[10], false);
        let mut bytes = fs::read(&path).unwrap();
        bytes[RING_HEADER_SIZE] ^= 1;
        fs::write(&path, &bytes).unwrap();
        assert!(read_ring_records(&path).unwrap().is_empty());
        assert!(!path.exists());
        let quarantined = fs::read_dir(&dir).unwrap().next().unwrap().unwrap().path();
        assert_eq!(fs::read(quarantined).unwrap(), bytes);
        fs::remove_dir_all(dir).unwrap();
    }

    fn sample_bucket(start: u64) -> AggregatedBucket {
        AggregatedBucket {
            start_ts_ms: start,
            end_ts_ms: start + 3_599_999,
            up_v4_bytes: 1,
            down_v4_bytes: 2,
            up_v6_bytes: 3,
            down_v6_bytes: 4,
            up_v4_bps_avg: 5,
            up_v4_bps_max: 6,
            up_v4_bps_min: 7,
            up_v4_bps_p95: 8,
            down_v4_bps_avg: 9,
            down_v4_bps_max: 10,
            down_v4_bps_min: 11,
            down_v4_bps_p95: 12,
            up_v6_bps_avg: 13,
            up_v6_bps_max: 14,
            up_v6_bps_min: 15,
            up_v6_bps_p95: 16,
            down_v6_bps_avg: 17,
            down_v6_bps_max: 18,
            down_v6_bps_min: 19,
            down_v6_bps_p95: 20,
            ..Default::default()
        }
    }

    #[test]
    fn ring_wrap_keeps_recent_records() {
        let dir = std::env::temp_dir().join(format!("bandix-plus-ring-test-{}", time_utils::now_millis()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("x.ring");

        for i in 0..(RING_SLOT_COUNT as usize + 10) {
            append_ring_record(
                &file,
                &RingRecord {
                    bucket: sample_bucket(i as u64),
                },
            )
            .unwrap();
        }

        let records = read_ring_records(&file).unwrap();
        assert_eq!(records.len(), RING_SLOT_COUNT as usize);
        assert_eq!(records.first().unwrap().bucket.start_ts_ms, 10);
        assert_eq!(
            records.last().unwrap().bucket.start_ts_ms,
            (RING_SLOT_COUNT as usize + 9) as u64
        );

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn ring_grows_on_demand_instead_of_preallocating_full_size() {
        let dir = std::env::temp_dir().join(format!("bandix-plus-ring-grow-test-{}", time_utils::now_millis()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("x.ring");

        append_ring_record(&file, &RingRecord { bucket: sample_bucket(1) }).unwrap();

        let size_after_one = fs::metadata(&file).unwrap().len();
        assert_eq!(size_after_one, (RING_HEADER_SIZE + RING_RECORD_SIZE) as u64);
        assert!(size_after_one < ring_total_size(&default_ring_header(RING_SLOT_COUNT)) as u64);

        append_ring_record(&file, &RingRecord { bucket: sample_bucket(2) }).unwrap();
        let size_after_two = fs::metadata(&file).unwrap().len();
        assert_eq!(size_after_two, (RING_HEADER_SIZE + 2 * RING_RECORD_SIZE) as u64);

        let _ = fs::remove_dir_all(dir);
    }
}
