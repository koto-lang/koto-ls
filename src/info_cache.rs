use crate::source_info::SourceInfo;
use std::{collections::HashMap, sync::Arc, time::SystemTime};
use tower_lsp::lsp_types::Url;

#[derive(Default, Debug)]
pub struct InfoCache {
    entries: HashMap<Arc<Url>, Info>,
}

impl InfoCache {
    pub fn insert(&mut self, url: Arc<Url>, version: Version, info: SourceInfo) {
        self.entries.insert(
            url,
            Info {
                info: Arc::new(info),
                version,
            },
        );
    }

    pub fn get(&self, url: &Url) -> Option<Arc<SourceInfo>> {
        self.entries.get(url).map(|info| info.info.clone())
    }

    pub fn get_versioned(&self, url: &Url, version: Version) -> Option<Arc<SourceInfo>> {
        match self.entries.get(url) {
            Some(info) if info.version == version => Some(info.info.clone()),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Info {
    pub info: Arc<SourceInfo>,
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
