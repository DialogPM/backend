//! Country of an IP address, from a local database file: nothing is asked of any service.
//!
//! The file is a CSV of address ranges, one per line: `first,last,CC` (IPv4 and IPv6, with
//! or without quotes), the format of the free "IP to Country Lite" database of DB-IP
//! (https://db-ip.com, CC BY 4.0: say "IP Geolocation by DB-IP" where the result is shown).
//! Set `CHATAPP_GEOIP_DB` to the unpacked file; without it the server keeps no country
//! statistics at all.
//!
//! The country is only ever added to a daily total (metrics.rs). Neither the address nor the
//! country is stored with an account, a device or a log line.

use std::io::BufRead;
use std::net::IpAddr;

/// ISO 3166-1 alpha-2, upper case.
pub type Country = [u8; 2];

/// An address the database does not cover (private ranges, a gap in the file).
pub const UNKNOWN: Country = *b"ZZ";

#[derive(Default)]
pub struct GeoIp {
    /// (first, last, country), sorted by `first`; ranges do not overlap.
    v4: Vec<(u32, u32, Country)>,
    v6: Vec<(u128, u128, Country)>,
}

impl GeoIp {
    pub fn load(path: &str) -> Result<GeoIp, String> {
        let file = std::fs::File::open(path).map_err(|e| format!("{path}: {e}"))?;
        let db = GeoIp::parse(std::io::BufReader::new(file)).map_err(|e| format!("{path}: {e}"))?;
        if db.v4.is_empty() && db.v6.is_empty() {
            return Err(format!("{path}: no address ranges (is the file still compressed?)"));
        }
        Ok(db)
    }

    pub fn parse(reader: impl BufRead) -> Result<GeoIp, String> {
        let mut db = GeoIp::default();
        for (n, line) in reader.lines().enumerate() {
            let line = line.map_err(|e| format!("line {}: {e}", n + 1))?;
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let mut fields = line.split(',').map(|f| f.trim().trim_matches('"'));
            let (Some(first), Some(last), Some(cc)) = (fields.next(), fields.next(), fields.next()) else {
                return Err(format!("line {}: expected first,last,country", n + 1));
            };
            let cc = cc.as_bytes();
            if cc.len() != 2 || !cc.iter().all(u8::is_ascii_alphabetic) {
                continue; // a range without a country
            }
            let country = [cc[0].to_ascii_uppercase(), cc[1].to_ascii_uppercase()];
            match (first.parse::<IpAddr>(), last.parse::<IpAddr>()) {
                (Ok(IpAddr::V4(a)), Ok(IpAddr::V4(b))) => db.v4.push((a.into(), b.into(), country)),
                (Ok(IpAddr::V6(a)), Ok(IpAddr::V6(b))) => db.v6.push((a.into(), b.into(), country)),
                // A header line, or a line of another kind.
                _ if n == 0 => continue,
                _ => return Err(format!("line {}: not a range of addresses", n + 1)),
            }
        }
        db.v4.sort_unstable_by_key(|r| r.0);
        db.v6.sort_unstable_by_key(|r| r.0);
        Ok(db)
    }

    pub fn ranges(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn country(&self, ip: IpAddr) -> Country {
        fn find<T: Ord + Copy>(ranges: &[(T, T, Country)], ip: T) -> Country {
            let i = ranges.partition_point(|r| r.0 <= ip);
            match i.checked_sub(1).map(|i| ranges[i]) {
                Some((_, last, country)) if ip <= last => country,
                _ => UNKNOWN,
            }
        }
        match ip.to_canonical() {
            IpAddr::V4(a) => find(&self.v4, u32::from(a)),
            IpAddr::V6(a) => find(&self.v6, u128::from(a)),
        }
    }
}

/// The database of a running server: read at start and again whenever the file changes (a
/// monthly update replaces it, scripts/geoip-update.sh), without a restart.
pub struct Shared {
    path: String,
    /// The loaded database and the modification time of the file it was read from.
    current: std::sync::RwLock<Option<(std::time::SystemTime, std::sync::Arc<GeoIp>)>>,
}

impl Shared {
    /// `path` empty: no country statistics.
    pub fn new(path: &str) -> Shared {
        let shared = Shared { path: path.to_string(), current: Default::default() };
        shared.reload_if_changed();
        shared
    }

    pub fn enabled(&self) -> bool {
        self.current.read().unwrap().is_some()
    }

    pub fn country(&self, ip: IpAddr) -> Option<Country> {
        let db = self.current.read().unwrap().as_ref().map(|(_, db)| db.clone())?;
        Some(db.country(ip))
    }

    /// Reads the file when it is new or was replaced. A file that cannot be read leaves the
    /// database in use as it is: statistics are not worth more than a warning.
    pub fn reload_if_changed(&self) {
        if self.path.is_empty() {
            return;
        }
        let modified = match std::fs::metadata(&self.path).and_then(|m| m.modified()) {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = %e, path = %self.path, "country database not readable");
                return;
            }
        };
        if self.current.read().unwrap().as_ref().is_some_and(|(at, _)| *at == modified) {
            return;
        }
        match GeoIp::load(&self.path) {
            Ok(db) => {
                tracing::info!(ranges = db.ranges(), "country statistics enabled");
                *self.current.write().unwrap() = Some((modified, std::sync::Arc::new(db)));
            }
            Err(e) => tracing::warn!(error = %e, "country database could not be read"),
        }
    }

    /// Looks at the file once an hour.
    pub async fn watch(state: crate::state::AppState) {
        let mut t = tokio::time::interval(std::time::Duration::from_secs(3600));
        t.tick().await;
        loop {
            t.tick().await;
            // Parsing takes a moment: not on the async workers.
            let st = state.clone();
            let _ = tokio::task::spawn_blocking(move || st.geoip.reload_if_changed()).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_replaced_file_is_read_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("db.csv");
        let ip: IpAddr = "5.2.200.7".parse().unwrap();
        assert!(!Shared::new("").enabled() && Shared::new("").country(ip).is_none());
        // Missing at start: disabled, and enabled once the file is there.
        let shared = Shared::new(path.to_str().unwrap());
        assert!(!shared.enabled());
        std::fs::write(&path, "5.2.128.0,5.2.255.255,RO\n").unwrap();
        shared.reload_if_changed();
        assert_eq!(shared.country(ip), Some(*b"RO"));
        // Replaced by a new file (another modification time), as the monthly update does.
        let next = dir.path().join("next.csv");
        std::fs::write(&next, "5.2.128.0,5.2.255.255,MD\n").unwrap();
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(5);
        std::fs::File::options().write(true).open(&next).unwrap().set_modified(later).unwrap();
        std::fs::rename(&next, &path).unwrap();
        shared.reload_if_changed();
        assert_eq!(shared.country(ip), Some(*b"MD"));
        // A broken replacement keeps the database in use.
        std::fs::write(&path, "not a database\nat all\n").unwrap();
        std::fs::File::options().write(true).open(&path).unwrap().set_modified(later + std::time::Duration::from_secs(5)).unwrap();
        shared.reload_if_changed();
        assert_eq!(shared.country(ip), Some(*b"MD"));
    }

    const SAMPLE: &str = "\
1.0.0.0,1.0.0.255,AU
\"5.2.128.0\",\"5.2.255.255\",\"RO\"
5.3.0.0,5.3.255.255,de
9.9.9.0,9.9.9.255,
2001:200::,2001:200:ffff:ffff:ffff:ffff:ffff:ffff,JP
2a02:2f00::,2a02:2f0f:ffff:ffff:ffff:ffff:ffff:ffff,RO
";

    fn cc(db: &GeoIp, ip: &str) -> String {
        String::from_utf8(db.country(ip.parse().unwrap()).to_vec()).unwrap()
    }

    #[test]
    fn addresses_map_to_their_country() {
        let db = GeoIp::parse(SAMPLE.as_bytes()).unwrap();
        assert_eq!(db.ranges(), 5, "the range without a country is left out");
        assert_eq!(cc(&db, "1.0.0.0"), "AU");
        assert_eq!(cc(&db, "1.0.0.255"), "AU");
        assert_eq!(cc(&db, "5.2.200.7"), "RO");
        assert_eq!(cc(&db, "5.3.1.1"), "DE", "lower case in the file");
        assert_eq!(cc(&db, "2001:200::1"), "JP");
        assert_eq!(cc(&db, "2a02:2f0a:1::5"), "RO");
        // An IPv4 client seen through an IPv6 socket.
        assert_eq!(cc(&db, "::ffff:5.2.200.7"), "RO");
    }

    #[test]
    fn addresses_outside_every_range_are_unknown() {
        let db = GeoIp::parse(SAMPLE.as_bytes()).unwrap();
        for ip in ["0.0.0.1", "1.0.1.0", "5.2.127.255", "9.9.9.9", "127.0.0.1", "10.0.0.1", "255.255.255.255", "::1", "2001:201::", "ffff::"] {
            assert_eq!(cc(&db, ip), "ZZ", "{ip}");
        }
        assert_eq!(cc(&GeoIp::default(), "1.0.0.1"), "ZZ");
    }

    #[test]
    fn a_header_line_is_skipped_and_garbage_is_refused() {
        let db = GeoIp::parse("ip_start,ip_end,country\n1.0.0.0,1.0.0.255,AU\n".as_bytes()).unwrap();
        assert_eq!(db.ranges(), 1);
        assert!(GeoIp::parse("1.0.0.0,1.0.0.255,AU\nnot,an,ip\n".as_bytes()).is_err());
        assert!(GeoIp::parse("1.0.0.0,1.0.0.255,AU\n1.0.0.0\n".as_bytes()).is_err());
        assert!(GeoIp::parse("1.0.0.0,2001:200::,AU\n1.0.0.0,2001:200::,AU\n".as_bytes()).is_err());
    }
}
