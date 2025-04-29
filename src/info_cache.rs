use crate::source_info::SourceInfo;
use std::{collections::HashMap, sync::Arc, time::SystemTime};
use tower_lsp_server::lsp_types::Uri;

/// A cache of analyzed sources
///
/// When a script is analyzed via [SourceInfo::new] it will recursively analyze any imported modules,
/// which are then added to the cache to prevent unnecessary reanalysis.
#[derive(Default, Debug)]
pub struct InfoCache {
    entries: HashMap<Arc<Uri>, Info>,
}

impl InfoCache {
    pub fn insert(&mut self, url: Arc<Uri>, version: Version, info: SourceInfo) {
        self.entries.insert(
            url,
            Info {
                info: Arc::new(info),
                version,
            },
        );
    }

    pub fn get(&self, url: &Uri) -> Option<Arc<SourceInfo>> {
        self.entries.get(url).map(|info| info.info.clone())
    }

    pub fn get_versioned(&self, url: &Uri, version: Version) -> Option<Arc<SourceInfo>> {
        match self.entries.get(url) {
            Some(info) if info.version == version => Some(info.info.clone()),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Info {
    /// The cached [SourceInfo]
    pub info: Arc<SourceInfo>,
    /// The version of the source that was analyzed
    pub version: Version,
}

#[derive(Debug, PartialEq)]
pub enum Version {
    I32(i32),
    Timestamp(SystemTime),
}

impl From<i32> for Version {
    fn from(value: i32) -> Version {
        Version::I32(value)
    }
}

impl From<SystemTime> for Version {
    fn from(value: SystemTime) -> Version {
        Version::Timestamp(value)
    }
}
