/// Utility methods Windows specific.
use winapi::shared::ntdef::PWCHAR;

/// Convert a PWSTR (UTF-16) to String.
/// Implement it as utility method since we cannot implement traits for type we do not own.
pub fn pwchar_to_string(source: PWCHAR) -> String {
    let mut end = source;

    unsafe {
        while *end != 0 {
            end = end.add(1);
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(
            source,
            end.offset_from(source) as _,
        ))
    }
}
