//! GDI screen capture — the whole virtual screen (all monitors) to JPEG.
//!
//! The blocking FFI sequence runs in `spawn_blocking`; the port stays async.
//! DPI awareness (`PER_MONITOR_AWARE_V2`) is requested once at construction
//! so physical pixels are captured regardless of scaling.

use async_trait::async_trait;

use crate::ports::driven::{
    CaptureError,
    ScreenCapturePort,
};

/// Default JPEG quality (0–100).
pub const DEFAULT_JPEG_QUALITY: u8 = 70;

/// GDI-based capture adapter.
#[derive(Debug)]
pub struct GdiScreenCapture {
    quality: u8,
}

impl GdiScreenCapture {
    /// Create the adapter; requests per-monitor-v2 DPI awareness (best-effort:
    /// a failure means scaling was already configured, which is fine).
    ///
    /// # Errors
    /// Never currently; the signature keeps adapter construction uniform for
    /// the composition root.
    pub fn new(quality: u8) -> Result<Self, CaptureError> {
        use windows::Win32::UI::HiDpi::{
            DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
            SetProcessDpiAwarenessContext,
        };
        // SAFETY: takes a constant context handle; failing means the process
        // DPI awareness is already configured.
        let _ =
            unsafe { SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2) };
        Ok(Self { quality })
    }
}

#[async_trait]
impl ScreenCapturePort for GdiScreenCapture {
    async fn capture(&self) -> Result<Vec<u8>, CaptureError> {
        let quality = self.quality;
        tokio::task::spawn_blocking(move || capture_blocking(quality))
            .await
            .map_err(|error| CaptureError::Join(error.to_string()))?
    }
}

/// RAII for the GDI objects of one capture. Drop order: bitmap → memory DC →
/// screen DC.
struct GdiObjects {
    screen_dc: windows::Win32::Graphics::Gdi::HDC,
    memory_dc: windows::Win32::Graphics::Gdi::HDC,
    bitmap: windows::Win32::Graphics::Gdi::HBITMAP,
}

impl Drop for GdiObjects {
    fn drop(&mut self) {
        use windows::Win32::Graphics::Gdi::{
            DeleteDC,
            DeleteObject,
            ReleaseDC,
        };
        // SAFETY: each handle was created by the matching call in
        // `capture_blocking` and is released exactly once here.
        unsafe {
            let _ = DeleteObject(self.bitmap);
            let _ = DeleteDC(self.memory_dc);
            let _ = ReleaseDC(None, self.screen_dc);
        }
    }
}

/// The whole capture: virtual-screen metrics → compatible DIB section →
/// `BitBlt` → BGRA pixels → JPEG.
#[allow(clippy::too_many_lines)] // one FFI sequence, kept linear on purpose
fn capture_blocking(quality: u8) -> Result<Vec<u8>, CaptureError> {
    use windows::Win32::{
        Graphics::Gdi::{
            BITMAPINFO,
            BITMAPINFOHEADER,
            BitBlt,
            CAPTUREBLT,
            CreateCompatibleDC,
            CreateDIBSection,
            DIB_RGB_COLORS,
            DeleteDC,
            GetDC,
            ReleaseDC,
            SRCCOPY,
            SelectObject,
        },
        UI::WindowsAndMessaging::{
            GetSystemMetrics,
            SM_CXVIRTUALSCREEN,
            SM_CYVIRTUALSCREEN,
            SM_XVIRTUALSCREEN,
            SM_YVIRTUALSCREEN,
        },
    };

    // SAFETY: metric queries and DC acquisition have no preconditions.
    let (origin_x, origin_y, width, height) = unsafe {
        (
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN),
            GetSystemMetrics(SM_CXVIRTUALSCREEN),
            GetSystemMetrics(SM_CYVIRTUALSCREEN),
        )
    };
    if width <= 0 || height <= 0 {
        return Err(CaptureError::Unavailable);
    }
    let dimensions = match (u16::try_from(width), u16::try_from(height)) {
        (Ok(w), Ok(h)) => (w, h),
        _ => {
            return Err(CaptureError::Gdi(format!(
                "virtual screen {width}x{height} exceeds JPEG dimensions"
            )));
        }
    };

    // SAFETY: DC acquisition with no preconditions.
    let screen_dc = unsafe { GetDC(None) };
    if screen_dc.is_invalid() {
        return Err(CaptureError::Gdi("GetDC(None) failed".to_owned()));
    }
    // SAFETY: compatible DC from a valid source DC.
    let memory_dc = unsafe { CreateCompatibleDC(screen_dc) };
    if memory_dc.is_invalid() {
        // SAFETY: releasing the DC acquired above.
        unsafe { ReleaseDC(None, screen_dc) };
        return Err(CaptureError::Gdi("CreateCompatibleDC failed".to_owned()));
    }

    let header = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: u32::try_from(std::mem::size_of::<BITMAPINFOHEADER>())
                .map_err(|error| CaptureError::Gdi(error.to_string()))?,
            biWidth: width,
            // Negative height = top-down scan order (row 0 is the top).
            biHeight: -height,
            biPlanes: 1,
            biBitCount: 32,
            ..BITMAPINFOHEADER::default()
        },
        ..BITMAPINFO::default()
    };
    let mut bits: *mut std::ffi::c_void = std::ptr::null_mut();
    // SAFETY: `header` is initialized above; `bits` receives the section's
    // backing memory, which stays alive while the bitmap handle exists.
    let bitmap = unsafe {
        CreateDIBSection(
            memory_dc,
            std::ptr::from_ref(&header),
            DIB_RGB_COLORS,
            std::ptr::from_mut(&mut bits),
            None,
            0,
        )
    };
    let bitmap = match bitmap {
        Ok(handle) if !handle.is_invalid() && !bits.is_null() => handle,
        Ok(_) | Err(_) => {
            // SAFETY: releasing objects this function created.
            unsafe {
                let _ = DeleteDC(memory_dc);
                let _ = ReleaseDC(None, screen_dc);
            }
            return Err(CaptureError::Gdi("CreateDIBSection failed".to_owned()));
        }
    };
    let objects = GdiObjects { screen_dc, memory_dc, bitmap };

    // SAFETY: valid DC and bitmap handle; the previously selected stock
    // object is restored below before the bitmap is deleted.
    let previous = unsafe { SelectObject(objects.memory_dc, objects.bitmap) };
    // SAFETY: valid DCs and coordinates from the metrics above.
    let blitted = unsafe {
        BitBlt(
            objects.memory_dc,
            0,
            0,
            width,
            height,
            objects.screen_dc,
            origin_x,
            origin_y,
            SRCCOPY | CAPTUREBLT,
        )
    };
    // SAFETY: restoring the stock object before the bitmap is deleted.
    unsafe { SelectObject(objects.memory_dc, previous) };
    blitted.map_err(|error| CaptureError::Gdi(format!("BitBlt failed: {error}")))?;

    let pixel_len = match (usize::try_from(width), usize::try_from(height)) {
        (Ok(w), Ok(h)) => w.checked_mul(h).and_then(|pixels| pixels.checked_mul(4)),
        _ => None,
    };
    let Some(pixel_len) = pixel_len else {
        return Err(CaptureError::Gdi("virtual screen size overflow".to_owned()));
    };
    // SAFETY: `bits` points at the DIB section's memory — exactly
    // `pixel_len` bytes of 32-bit BGRA pixels, valid until `objects` drops.
    let pixels = unsafe { std::slice::from_raw_parts(bits.cast::<u8>(), pixel_len) }.to_vec();
    drop(objects);

    encode_bgra_jpeg(&pixels, dimensions.0, dimensions.1, quality).map_err(CaptureError::Encode)
}

/// Encode 32-bit BGRA pixels as JPEG (alpha ignored).
fn encode_bgra_jpeg(
    pixels: &[u8],
    width: u16,
    height: u16,
    quality: u8,
) -> Result<Vec<u8>, String> {
    let mut jpeg = Vec::new();
    let encoder = jpeg_encoder::Encoder::new(&mut jpeg, quality.clamp(1, 100));
    encoder
        .encode(pixels, width, height, jpeg_encoder::ColorType::Bgra)
        .map_err(|error| error.to_string())?;
    Ok(jpeg)
}
