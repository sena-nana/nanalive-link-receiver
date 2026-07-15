fn rec709_limited_premultiplied_bgra(y: u8, cb: u8, cr: u8, alpha: u8) -> [u8; 4] {
    let y = (f32::from(y) - 16.0).max(0.0) / 219.0;
    let cb = (f32::from(cb) - 128.0) / 224.0;
    let cr = (f32::from(cr) - 128.0) / 224.0;
    let alpha = f32::from(alpha) / 255.0;
    let red = (y + 1.5748 * cr).clamp(0.0, 1.0) * alpha;
    let green = (y - 0.187_324 * cb - 0.468_124 * cr).clamp(0.0, 1.0) * alpha;
    let blue = (y + 1.8556 * cb).clamp(0.0, 1.0) * alpha;
    let byte = |value: f32| (value * 255.0).round() as u8;
    [byte(blue), byte(green), byte(red), byte(alpha)]
}

#[test]
fn black_white_and_alpha_extremes_follow_premultiplied_bgra_contract() {
    assert_eq!(
        rec709_limited_premultiplied_bgra(16, 128, 128, 255),
        [0, 0, 0, 255]
    );
    assert_eq!(
        rec709_limited_premultiplied_bgra(235, 128, 128, 255),
        [255, 255, 255, 255]
    );
    assert_eq!(
        rec709_limited_premultiplied_bgra(235, 128, 128, 0),
        [0, 0, 0, 0]
    );
    assert_eq!(
        rec709_limited_premultiplied_bgra(235, 128, 128, 1),
        [1, 1, 1, 1]
    );
    assert_eq!(
        rec709_limited_premultiplied_bgra(235, 128, 128, 128),
        [128, 128, 128, 128]
    );
}

#[test]
fn rec709_red_is_stored_as_premultiplied_bgra() {
    let opaque = rec709_limited_premultiplied_bgra(63, 102, 240, 255);
    assert!(opaque[0] <= 2, "blue channel: {}", opaque[0]);
    assert!(opaque[1] <= 2, "green channel: {}", opaque[1]);
    assert!(opaque[2] >= 253, "red channel: {}", opaque[2]);
    assert_eq!(opaque[3], 255);

    let partial = rec709_limited_premultiplied_bgra(63, 102, 240, 128);
    assert!(partial[0] <= 1);
    assert!(partial[1] <= 1);
    assert!((127..=128).contains(&partial[2]));
    assert_eq!(partial[3], 128);
}
