//! Live entries indexed by an eagerly maintained min-heap. Completed/evicted
//! entries remove their heap node immediately: no traffic-proportional history.
//! Deadline lookup is O(1); removal/expiry is O(log n) per removed entry.

use super::*;

struct Entry<T> {
    value: T,
    position: usize,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Deadline {
    at: Instant,
    key: AssemblyKey,
}

pub(super) struct Pending<T> {
    entries: HashMap<AssemblyKey, Entry<T>>,
    deadlines: Vec<Deadline>,
}

impl<T> Default for Pending<T> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            deadlines: Vec::new(),
        }
    }
}

impl<T> Pending<T> {
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub(super) fn contains_key(&self, key: &AssemblyKey) -> bool {
        self.entries.contains_key(key)
    }

    pub(super) fn get(&self, key: &AssemblyKey) -> Option<&T> {
        self.entries.get(key).map(|entry| &entry.value)
    }

    pub(super) fn get_mut(&mut self, key: &AssemblyKey) -> Option<&mut T> {
        self.entries.get_mut(key).map(|entry| &mut entry.value)
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = (&AssemblyKey, &T)> {
        self.entries.iter().map(|(key, entry)| (key, &entry.value))
    }

    pub(super) fn values(&self) -> impl Iterator<Item = &T> {
        self.entries.values().map(|entry| &entry.value)
    }

    pub(super) fn deadline(&self) -> Option<Instant> {
        self.deadlines.first().map(|entry| entry.at)
    }

    pub(super) fn oldest(&self) -> Option<AssemblyKey> {
        self.deadlines.first().map(|entry| entry.key)
    }

    pub(super) fn insert(&mut self, key: AssemblyKey, value: T, at: Instant) {
        let position = self.deadlines.len();
        match self.entries.entry(key) {
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(Entry { value, position });
            }
            std::collections::hash_map::Entry::Occupied(_) => {
                // Replacement must remove the old deadline too (including ID reuse).
                self.remove(&key);
                self.insert(key, value, at);
                return;
            }
        }
        self.deadlines.push(Deadline { at, key });
        self.sift_up(position);
    }

    pub(super) fn remove(&mut self, key: &AssemblyKey) -> Option<T> {
        let entry = self.entries.remove(key)?;
        self.deadlines.swap_remove(entry.position);
        if entry.position < self.deadlines.len() {
            self.entries
                .get_mut(&self.deadlines[entry.position].key)
                .unwrap()
                .position = entry.position;
            if entry.position > 0
                && self.deadlines[entry.position] < self.deadlines[(entry.position - 1) / 2]
            {
                self.sift_up(entry.position);
            } else {
                self.sift_down(entry.position);
            }
        }
        Some(entry.value)
    }

    pub(super) fn expire(&mut self, now: Instant) -> usize {
        let mut expired = 0;
        while let Some(first) = self.deadlines.first()
            && now >= first.at
        {
            let key = first.key;
            self.remove(&key);
            expired += 1;
        }
        expired
    }

    fn swap(&mut self, a: usize, b: usize) {
        self.deadlines.swap(a, b);
        self.entries
            .get_mut(&self.deadlines[a].key)
            .unwrap()
            .position = a;
        self.entries
            .get_mut(&self.deadlines[b].key)
            .unwrap()
            .position = b;
    }

    fn sift_up(&mut self, mut position: usize) {
        while position > 0 {
            let parent = (position - 1) / 2;
            if self.deadlines[parent] <= self.deadlines[position] {
                break;
            }
            self.swap(parent, position);
            position = parent;
        }
    }

    fn sift_down(&mut self, mut position: usize) {
        loop {
            let left = 2 * position + 1;
            if left >= self.deadlines.len() {
                break;
            }
            let right = left + 1;
            let child =
                if right < self.deadlines.len() && self.deadlines[right] < self.deadlines[left] {
                    right
                } else {
                    left
                };
            if self.deadlines[position] <= self.deadlines[child] {
                break;
            }
            self.swap(position, child);
            position = child;
        }
    }
}

impl<T> FromIterator<(AssemblyKey, T, Instant)> for Pending<T> {
    fn from_iter<I: IntoIterator<Item = (AssemblyKey, T, Instant)>>(iter: I) -> Self {
        let mut pending = Self::default();
        for (key, value, at) in iter {
            pending.insert(key, value, at);
        }
        pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn index_matches_sorted_live_entries(
            operations in prop::collection::vec((0u8..4, 0u8..64, 0u16..1000), 1..2000)
        ) {
            let mut pending = Pending::default();
            let mut model = HashMap::new();
            let now = Instant::now();
            for (op, id, millis) in operations {
                let key = AssemblyKey { handle: 1 + u16::from(id % 3), id: u64::from(id) };
                let at = now + Duration::from_millis(u64::from(millis));
                match op {
                    0 | 1 => { pending.insert(key, millis, at); model.insert(key, (millis, at)); }
                    2 => { prop_assert_eq!(pending.remove(&key), model.remove(&key).map(|v| v.0)); }
                    _ => {
                        let before = model.len();
                        model.retain(|_, (_, deadline)| *deadline > at);
                        prop_assert_eq!(pending.expire(at), before - model.len());
                    }
                }
                let oldest = model.iter().min_by_key(|(key, (_, at))| (*at, **key));
                prop_assert_eq!(pending.oldest(), oldest.map(|(key, _)| *key));
                prop_assert_eq!(pending.deadline(), oldest.map(|(_, (_, at))| *at));
                prop_assert_eq!(pending.deadlines.len(), model.len());
                prop_assert_eq!(pending.len(), model.len());
                for (position, deadline) in pending.deadlines.iter().enumerate() {
                    prop_assert_eq!(pending.entries[&deadline.key].position, position);
                    prop_assert_eq!(pending.get(&deadline.key).copied(), model.get(&deadline.key).map(|v| v.0));
                }
            }
        }
    }

    #[test]
    fn completed_entries_leave_no_deadline_history() {
        let mut pending = Pending::default();
        let now = Instant::now();
        for id in 0..100_000 {
            let key = AssemblyKey { handle: 1, id };
            pending.insert(key, (), now);
            pending.remove(&key);
            assert!(pending.deadlines.is_empty());
            assert!(pending.is_empty());
        }
        assert!(pending.deadline().is_none());
    }
}
