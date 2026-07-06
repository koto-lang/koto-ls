use crate::source_info::SourceInfo;
use std::{
    collections::{HashMap, HashSet},
    ops::{Deref, DerefMut},
    sync::Arc,
    time::SystemTime,
};
use tower_lsp_server::lsp_types::Uri;

/// A cache of analyzed sources
///
/// When a script is analyzed via [SourceInfo::new] it will recursively analyze any imported modules,
/// which are then added to the cache to prevent unnecessary reanalysis.
#[derive(Default, Debug)]
pub struct InfoCache {
    entries: HashMap<Arc<Uri>, Info>,
    // Sources that are currently being analyzed, used to prevent recursive analysis.
    in_progress: HashSet<Arc<Uri>>,
}

impl InfoCache {
    /// Marks a source URI as currently being analyzed.
    ///
    /// Returns an [AnalysisGuard] when the URI wasn't already in progress,
    /// or `None` if analysis for the URI is already in progress.
    pub fn begin_analysis(&mut self, url: Arc<Uri>) -> Option<AnalysisGuard<'_>> {
        if self.in_progress.insert(url.clone()) {
            Some(AnalysisGuard {
                info_cache: self,
                url,
            })
        } else {
            None
        }
    }

    fn end_analysis(&mut self, url: &Uri) {
        self.in_progress.remove(url);
    }

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

/// Scoped helper returned by [InfoCache::begin_analysis].
///
/// The helper automatically calls [InfoCache::end_analysis] for the URI when dropped.
pub struct AnalysisGuard<'a> {
    info_cache: &'a mut InfoCache,
    url: Arc<Uri>,
}

impl Deref for AnalysisGuard<'_> {
    type Target = InfoCache;

    fn deref(&self) -> &Self::Target {
        self.info_cache
    }
}

impl DerefMut for AnalysisGuard<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.info_cache
    }
}

impl Drop for AnalysisGuard<'_> {
    fn drop(&mut self) {
        self.info_cache.end_analysis(&self.url);
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
