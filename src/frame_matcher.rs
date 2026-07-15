use std::collections::BTreeMap;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PlaneViewDimension {
    Texture2D {
        most_detailed_mip: u32,
    },
    Texture2DArray {
        most_detailed_mip: u32,
        first_array_slice: u32,
    },
}

pub(crate) fn select_plane_view_dimension(
    array_size: u32,
    mip_levels: u32,
    subresource: u32,
) -> Result<PlaneViewDimension, &'static str> {
    if array_size == 0 || mip_levels == 0 || subresource >= array_size.saturating_mul(mip_levels) {
        return Err("decoded D3D11 texture subresource is outside its texture");
    }
    let most_detailed_mip = subresource % mip_levels;
    let first_array_slice = subresource / mip_levels;
    if array_size == 1 {
        Ok(PlaneViewDimension::Texture2D { most_detailed_mip })
    } else {
        Ok(PlaneViewDimension::Texture2DArray {
            most_detailed_mip,
            first_array_slice,
        })
    }
}

pub(crate) struct PendingAlphaFrames {
    capacity: usize,
    frames: BTreeMap<u64, (u32, Vec<u8>)>,
}

impl PendingAlphaFrames {
    pub(crate) fn new(capacity: usize) -> Self {
        assert!(capacity > 0);
        Self {
            capacity,
            frames: BTreeMap::new(),
        }
    }

    pub(crate) fn insert(&mut self, pts_us: u64, frame_id: u32, alpha: Vec<u8>) {
        self.frames.insert(pts_us, (frame_id, alpha));
        while self.frames.len() > self.capacity {
            let oldest = *self.frames.keys().next().expect("non-empty pending alpha");
            self.frames.remove(&oldest);
        }
    }

    #[cfg(windows)]
    pub(crate) fn len(&self) -> usize {
        self.frames.len()
    }

    pub(crate) fn take_latest_matching(
        &mut self,
        decoded_pts: impl IntoIterator<Item = u64>,
    ) -> Option<(u64, u32, Vec<u8>)> {
        let pts_us = decoded_pts
            .into_iter()
            .filter(|pts| self.frames.contains_key(pts))
            .max()?;
        let (frame_id, alpha) = self.frames.remove(&pts_us)?;
        self.frames.retain(|pts, _| *pts > pts_us);
        Some((pts_us, frame_id, alpha))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delayed_decoder_output_matches_its_own_alpha_and_publishes_latest_pair() {
        let mut pending = PendingAlphaFrames::new(2);
        pending.insert(1_000, 1, vec![10]);
        assert!(pending.take_latest_matching([]).is_none());
        pending.insert(2_000, 2, vec![20]);
        let matched = pending.take_latest_matching([1_000, 2_000]).unwrap();
        assert_eq!(matched, (2_000, 2, vec![20]));
        assert!(pending.take_latest_matching([1_000]).is_none());
    }

    #[test]
    fn pending_alpha_is_bounded_to_receiver_inflight_limit() {
        let mut pending = PendingAlphaFrames::new(2);
        pending.insert(1, 1, vec![1]);
        pending.insert(2, 2, vec![2]);
        pending.insert(3, 3, vec![3]);
        assert!(pending.take_latest_matching([1]).is_none());
        assert_eq!(pending.take_latest_matching([2]).unwrap().1, 2);
    }

    #[test]
    fn plane_view_dimension_matches_texture_shape_and_validates_subresource() {
        assert_eq!(
            select_plane_view_dimension(1, 1, 0),
            Ok(PlaneViewDimension::Texture2D {
                most_detailed_mip: 0
            })
        );
        assert_eq!(
            select_plane_view_dimension(4, 2, 5),
            Ok(PlaneViewDimension::Texture2DArray {
                most_detailed_mip: 1,
                first_array_slice: 2
            })
        );
        assert!(select_plane_view_dimension(1, 1, 1).is_err());
        assert!(select_plane_view_dimension(2, 1, 2).is_err());
        assert!(select_plane_view_dimension(0, 1, 0).is_err());
        assert!(select_plane_view_dimension(1, 0, 0).is_err());
    }
}
