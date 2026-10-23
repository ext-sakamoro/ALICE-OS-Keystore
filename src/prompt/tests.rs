//! The line collector and the UTF-16 decoder on scripted input: limits,
//! terminators, every way out, and that the buffers are zero afterwards
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::line::{collect_line, line_buf};
use super::utf16::{Utf16Bytes, INVALID};
use super::{PromptError, MAX_SECRET_LEN};

/// Runs the collector on `input` (then the end of the input) and checks the buffer is zero after
fn collect(input: &[u8]) -> Result<String, PromptError> {
    let mut buf = line_buf();
    let mut it = input.iter().copied();
    let r = collect_line(&mut buf, || Ok(it.next()));
    assert!(
        buf.iter().all(|&b| b == 0),
        "the line buffer was not zeroed"
    );
    r.map(|s| s.as_str().to_owned())
}

#[test]
fn a_line_of_exactly_the_limit_is_read_and_one_byte_more_is_refused() {
    let mut at_limit = vec![b'a'; MAX_SECRET_LEN];
    at_limit.push(b'\n');
    assert_eq!(collect(&at_limit).unwrap().len(), MAX_SECRET_LEN);
    let mut over = vec![b'a'; MAX_SECRET_LEN + 1];
    over.push(b'\n');
    assert!(matches!(collect(&over), Err(PromptError::TooLong)));
    // a much longer line is consumed to its end: the byte after it is not read
    let mut long = vec![b'b'; 4 * MAX_SECRET_LEN];
    long.extend_from_slice(b"\nnext");
    let mut it = long.iter().copied();
    let mut buf = line_buf();
    let r = collect_line(&mut buf, || Ok(it.next()));
    assert!(matches!(r, Err(PromptError::TooLong)), "{r:?}");
    assert_eq!(it.collect::<Vec<_>>(), b"next");
}

#[test]
fn a_carriage_return_or_a_line_feed_ends_the_line() {
    assert_eq!(collect(b"abc\r").unwrap(), "abc");
    assert_eq!(collect(b"abc\n").unwrap(), "abc");
    // the first terminator ends it: what follows is left unread
    let input = b"ab\r\ncd";
    let mut it = input.iter().copied();
    let mut buf = line_buf();
    assert_eq!(
        collect_line(&mut buf, || Ok(it.next())).unwrap().as_str(),
        "ab"
    );
    assert_eq!(it.collect::<Vec<_>>(), b"\ncd");
}

#[test]
fn every_way_out_leaves_the_buffer_zero() {
    assert!(matches!(collect(b"\n"), Err(PromptError::Empty)));
    assert!(matches!(collect(b"abc"), Err(PromptError::Closed)));
    assert!(matches!(collect(b"ab\xffcd\n"), Err(PromptError::NotUtf8)));
    assert_eq!(collect("秘密\n".as_bytes()).unwrap(), "秘密");

    // an error from the input after some bytes were stored
    let mut buf = line_buf();
    let mut n = 0;
    let r = collect_line(&mut buf, || {
        n += 1;
        if n < 4 {
            Ok(Some(b's'))
        } else {
            Err(PromptError::Io(std::io::Error::other("injected")))
        }
    });
    assert!(matches!(r, Err(PromptError::Io(_))), "{r:?}");
    assert!(
        buf.iter().all(|&b| b == 0),
        "not zeroed after an input error"
    );

    // a panic in the input after some bytes were stored
    let mut buf = line_buf();
    let mut n = 0;
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        collect_line(&mut buf, || {
            n += 1;
            assert!(n < 4, "injected");
            Ok(Some(b's'))
        })
    }));
    assert!(r.is_err(), "the injected panic did not happen");
    assert!(buf.iter().all(|&b| b == 0), "not zeroed after a panic");
}

/// Feeds `units` and takes every byte, checking nothing is held between units
fn decode(units: &[u16]) -> Vec<u8> {
    let mut d = Utf16Bytes::default();
    let mut out = Vec::new();
    for &u in units {
        d.feed(u);
        while let Some(b) = d.next_byte() {
            out.push(b);
        }
    }
    out
}

#[test]
fn utf16_units_become_the_same_text_in_utf8() {
    for text in [
        "a",
        "pässwörd",
        "秘密の言葉",
        "😀 x 🔑",
        "\r\n",
        "\u{FFFF}\u{10FFFF}",
    ] {
        let units: Vec<u16> = text.encode_utf16().collect();
        assert_eq!(decode(&units), text.as_bytes(), "{text:?}");
    }
}

#[test]
fn an_unpaired_surrogate_becomes_a_byte_that_is_not_utf8() {
    // a low half alone, a high half followed by a letter, a high half at the end of the line
    assert_eq!(decode(&[0xDC00, 0x61]), [INVALID, b'a']);
    assert_eq!(decode(&[0xD83D, 0x61]), [INVALID, b'a']);
    assert_eq!(decode(&[0xD83D, 0x0D]), [INVALID, b'\r']);
    // two high halves: the first is unpaired, the second pairs with the low half
    let mut expected = vec![INVALID];
    expected.extend_from_slice("😀".as_bytes());
    assert_eq!(decode(&[0xD83D, 0xD83D, 0xDE00]), expected);
    // through the collector the line is refused, not changed
    let units: Vec<u16> = [0x61, 0xDC00, 0x62, 0x0A].to_vec();
    let bytes = decode(&units);
    assert!(matches!(collect(&bytes), Err(PromptError::NotUtf8)));
}

#[test]
fn the_decoder_holds_nothing_once_its_bytes_are_taken() {
    let mut d = Utf16Bytes::default();
    for u in "秘😀".encode_utf16() {
        d.feed(u);
        while d.next_byte().is_some() {}
    }
    assert!(d.is_clear(), "bytes or a half were left after being taken");
    // a high half waits (it is the only thing held) until its pair arrives
    d.feed(0xD83D);
    assert!(d.next_byte().is_none());
    assert!(!d.is_clear());
    d.feed(0xDE00);
    while d.next_byte().is_some() {}
    assert!(d.is_clear());
}

/// Dropping the decoder zeroes what it still holds: a waiting high half and
/// bytes not taken (the state an error or the end of the input leaves behind)
#[test]
fn dropping_the_decoder_leaves_its_storage_zero() {
    use crate::sys::watch_alloc::freed_all_zero;
    // a waiting high half
    let mut d = Box::new(Utf16Bytes::default());
    d.feed(0xD83D);
    assert!(!d.is_clear());
    assert!(freed_all_zero(d), "a waiting half was left in freed memory");
    // bytes not taken
    let mut d = Box::new(Utf16Bytes::default());
    d.feed(u16::from(b'k'));
    assert!(!d.is_clear());
    assert!(
        freed_all_zero(d),
        "bytes not taken were left in freed memory"
    );
    // the allocator check has teeth: a block freed with data is reported
    assert!(!freed_all_zero(Box::new([0x5Au8; 16])));
}
