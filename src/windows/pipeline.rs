use crate::frame_matcher::{PendingAlphaFrames, PlaneViewDimension, select_plane_view_dimension};
use crate::receiver::PreparedFrame;
use anyhow::{Context, Result, anyhow, bail};
use nanalive_spout::{GpuDx11PublishOptions, GpuDx11TextureSender, SpoutPublishStatus};
use std::mem::ManuallyDrop;
use std::ptr::null_mut;
use std::time::Instant;
use windows::Win32::Foundation::HMODULE;
use windows::Win32::Graphics::Direct3D::Fxc::D3DCompile;
use windows::Win32::Graphics::Direct3D::{
    D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL_11_0, D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST, ID3DBlob,
};
use windows::Win32::Graphics::Direct3D11::{
    D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, D3D11_CREATE_DEVICE_BGRA_SUPPORT,
    D3D11_CREATE_DEVICE_VIDEO_SUPPORT, D3D11_SDK_VERSION, D3D11_SHADER_RESOURCE_VIEW_DESC1,
    D3D11_SHADER_RESOURCE_VIEW_DESC1_0, D3D11_TEX2D_ARRAY_SRV1, D3D11_TEX2D_SRV1,
    D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT, D3D11_VIEWPORT, D3D11CreateDevice, ID3D11Device,
    ID3D11Device3, ID3D11DeviceContext, ID3D11PixelShader, ID3D11RenderTargetView,
    ID3D11ShaderResourceView, ID3D11ShaderResourceView1, ID3D11Texture2D, ID3D11VertexShader,
};
use windows::Win32::Graphics::Dxgi::Common::{
    DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_FORMAT_R8_UNORM, DXGI_FORMAT_R8G8_UNORM, DXGI_SAMPLE_DESC,
};
use windows::Win32::Media::MediaFoundation::{
    IMFActivate, IMFAttributes, IMFDXGIBuffer, IMFMediaType, IMFTransform, MF_E_NOTACCEPTING,
    MF_E_TRANSFORM_NEED_MORE_INPUT, MF_LOW_LATENCY, MF_MT_FRAME_SIZE, MF_MT_INTERLACE_MODE,
    MF_MT_MAJOR_TYPE, MF_MT_SUBTYPE, MF_SA_D3D11_AWARE, MF_VERSION, MFCreateDXGIDeviceManager,
    MFCreateMediaType, MFCreateMemoryBuffer, MFCreateSample, MFMediaType_Video, MFShutdown,
    MFStartup, MFT_CATEGORY_VIDEO_DECODER, MFT_ENUM_FLAG_HARDWARE, MFT_ENUM_FLAG_SORTANDFILTER,
    MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, MFT_MESSAGE_NOTIFY_END_OF_STREAM,
    MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_MESSAGE_SET_D3D_MANAGER, MFT_OUTPUT_DATA_BUFFER,
    MFT_OUTPUT_STREAM_PROVIDES_SAMPLES, MFT_REGISTER_TYPE_INFO, MFTEnumEx, MFVideoFormat_H264,
    MFVideoFormat_NV12, MFVideoInterlace_Progressive,
};
use windows::Win32::System::Com::{
    COINIT_MULTITHREADED, CoInitializeEx, CoTaskMemFree, CoUninitialize,
};
use windows::core::{Interface, PCSTR};

const SHADER: &[u8] = br#"
Texture2D<float> yPlane : register(t0);
Texture2D<float2> uvPlane : register(t1);
Texture2D<float> alphaPlane : register(t2);

struct VertexOutput { float4 position : SV_POSITION; };

VertexOutput vs_main(uint id : SV_VertexID) {
    float2 position = float2((id << 1) & 2, id & 2);
    VertexOutput output;
    output.position = float4(position * float2(2, -2) + float2(-1, 1), 0, 1);
    return output;
}

float4 ps_main(VertexOutput input) : SV_TARGET {
    int2 pixel = int2(input.position.xy);
    float y = (yPlane.Load(int3(pixel, 0)) - (16.0 / 255.0)) * (255.0 / 219.0);
    float2 uv = (uvPlane.Load(int3(pixel / 2, 0)) - (128.0 / 255.0)) * (255.0 / 224.0);
    float3 rgb = saturate(float3(
        y + 1.5748 * uv.y,
        y - 0.187324 * uv.x - 0.468124 * uv.y,
        y + 1.8556 * uv.x));
    float alpha = alphaPlane.Load(int3(pixel, 0));
    return float4(rgb * alpha, alpha);
}
"#;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PublishResult {
    Sent,
    SkippedAccessTimeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublishedFrame {
    pub frame_id: u32,
    pub result: PublishResult,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PipelineTelemetry {
    /// CPU time spent submitting input and draining available MF output.
    pub color_decode_submit_cpu_us: u32,
    /// CPU time spent recording the D3D11 composite commands. This is not GPU execution time.
    pub composite_enqueue_cpu_us: u32,
    /// CPU time spent in the Spout texture-publish call. This is not GPU copy time.
    pub spout_publish_cpu_us: u32,
}

pub struct HardwarePipeline {
    _com: ComRuntime,
    _mf: MediaFoundationRuntime,
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    decoder: HardwareH264Decoder,
    compositor: GpuCompositor,
    spout: GpuDx11TextureSender,
    pending_alpha: PendingAlphaFrames,
    telemetry: PipelineTelemetry,
}

impl HardwarePipeline {
    pub fn new(name: &str, width: u32, height: u32) -> Result<Self> {
        let com = ComRuntime::start()?;
        let mf = MediaFoundationRuntime::start()?;
        let (device, context) = create_device()?;
        let decoder = HardwareH264Decoder::new(&device, width, height)?;
        let compositor = GpuCompositor::new(&device, width, height)?;
        let spout = unsafe {
            GpuDx11TextureSender::new(name, device.as_raw().cast(), context.as_raw().cast())
        }
        .context("create GPU DX11 Spout sender")?;
        Ok(Self {
            _com: com,
            _mf: mf,
            device,
            context,
            decoder,
            compositor,
            spout,
            pending_alpha: PendingAlphaFrames::new(2),
            telemetry: PipelineTelemetry::default(),
        })
    }

    pub const fn telemetry(&self) -> PipelineTelemetry {
        self.telemetry
    }

    /// Frames submitted to Media Foundation whose matching output has not yet
    /// been returned. The bounded Alpha sidecar is the receiver-owned queue
    /// correlated with decoder PTS values.
    pub fn decode_queue_depth(&self) -> u16 {
        u16::try_from(self.pending_alpha.len()).unwrap_or(u16::MAX)
    }

    pub fn publish(&mut self, frame: &PreparedFrame) -> Result<Option<PublishedFrame>> {
        if frame.width != self.compositor.width || frame.height != self.compositor.height {
            bail!("frame dimensions changed without reconfiguration");
        }
        self.pending_alpha
            .insert(frame.pts_us, frame.frame_id, frame.alpha.clone());
        let decode_started = Instant::now();
        let decoded = self.decoder.submit(&frame.h264, frame.pts_us)?;
        self.telemetry.color_decode_submit_cpu_us = elapsed_us(decode_started);
        let Some((matched_pts, frame_id, alpha)) = self
            .pending_alpha
            .take_latest_matching(decoded.iter().map(|value| value.pts_us))
        else {
            return Ok(None);
        };
        let decoded = decoded
            .into_iter()
            .find(|value| value.pts_us == matched_pts)
            .expect("matched decoded timestamp came from decoder outputs");
        let composite_started = Instant::now();
        let output = self
            .compositor
            .composite(&self.device, &self.context, &decoded, &alpha)?;
        self.telemetry.composite_enqueue_cpu_us = elapsed_us(composite_started);
        let publish_started = Instant::now();
        let report = unsafe {
            self.spout.publish_texture(
                output.as_raw().cast(),
                GpuDx11PublishOptions::bgra8(frame.width, frame.height),
            )
        }
        .context("publish D3D11 texture to Spout")?;
        self.telemetry.spout_publish_cpu_us = elapsed_us(publish_started);
        match report.status {
            SpoutPublishStatus::Sent => Ok(Some(PublishedFrame {
                frame_id,
                result: PublishResult::Sent,
            })),
            SpoutPublishStatus::SkippedAccessTimeout => Ok(Some(PublishedFrame {
                frame_id,
                result: PublishResult::SkippedAccessTimeout,
            })),
            status => bail!("Spout publish failed with status {status:?}"),
        }
    }
}

fn elapsed_us(started: Instant) -> u32 {
    u32::try_from(started.elapsed().as_micros()).unwrap_or(u32::MAX)
}

fn create_device() -> Result<(ID3D11Device, ID3D11DeviceContext)> {
    unsafe {
        let mut device = None;
        let mut context = None;
        D3D11CreateDevice(
            None,
            D3D_DRIVER_TYPE_HARDWARE,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
            Some(&[D3D_FEATURE_LEVEL_11_0]),
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )
        .context("create D3D11 hardware device")?;
        Ok((
            device.context("D3D11 returned no device")?,
            context.context("D3D11 returned no immediate context")?,
        ))
    }
}

struct ComRuntime;

impl ComRuntime {
    fn start() -> Result<Self> {
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED).ok() }.context("initialize COM")?;
        Ok(Self)
    }
}

impl Drop for ComRuntime {
    fn drop(&mut self) {
        unsafe { CoUninitialize() };
    }
}

struct MediaFoundationRuntime;

impl MediaFoundationRuntime {
    fn start() -> Result<Self> {
        unsafe { MFStartup(MF_VERSION, 0) }.context("start Media Foundation")?;
        Ok(Self)
    }
}

impl Drop for MediaFoundationRuntime {
    fn drop(&mut self) {
        let _ = unsafe { MFShutdown() };
    }
}

struct DecodedTexture {
    texture: ID3D11Texture2D,
    subresource: u32,
    pts_us: u64,
}

struct HardwareH264Decoder {
    transform: IMFTransform,
    _device_manager: windows::Win32::Media::MediaFoundation::IMFDXGIDeviceManager,
}

impl HardwareH264Decoder {
    fn new(device: &ID3D11Device, width: u32, height: u32) -> Result<Self> {
        unsafe {
            let mut reset_token = 0;
            let mut manager = None;
            MFCreateDXGIDeviceManager(&mut reset_token, &mut manager)
                .context("create Media Foundation DXGI manager")?;
            let manager = manager.context("Media Foundation returned no DXGI manager")?;
            manager
                .ResetDevice(device, reset_token)
                .context("attach D3D11 device to Media Foundation")?;

            let transform = activate_hardware_decoder()?;
            let attributes = transform
                .GetAttributes()
                .context("query decoder attributes")?;
            if attributes.GetUINT32(&MF_SA_D3D11_AWARE).unwrap_or(0) == 0 {
                bail!("the selected H.264 decoder is not D3D11-aware");
            }
            attributes.SetUINT32(&MF_LOW_LATENCY, 1).ok();
            transform
                .ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, manager.as_raw() as usize)
                .context("bind decoder to the receiver D3D11 device")?;

            let input = video_type(MFVideoFormat_H264, width, height)?;
            let output = video_type(MFVideoFormat_NV12, width, height)?;
            output
                .cast::<IMFAttributes>()?
                .SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)?;
            transform
                .SetInputType(0, &input, 0)
                .context("set H.264 input type")?;
            transform
                .SetOutputType(0, &output, 0)
                .context("set NV12 output type")?;
            let output_info = transform.GetOutputStreamInfo(0)?;
            if output_info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32 == 0 {
                bail!("hardware decoder does not provide zero-copy D3D11 output samples");
            }
            transform.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)?;
            transform.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)?;
            Ok(Self {
                transform,
                _device_manager: manager,
            })
        }
    }

    fn submit(&mut self, access_unit: &[u8], pts_us: u64) -> Result<Vec<DecodedTexture>> {
        unsafe {
            let length = u32::try_from(access_unit.len()).context("H.264 access unit too large")?;
            let buffer = MFCreateMemoryBuffer(length)?;
            let mut destination = null_mut();
            buffer.Lock(&mut destination, None, None)?;
            std::ptr::copy_nonoverlapping(access_unit.as_ptr(), destination, access_unit.len());
            buffer.Unlock()?;
            buffer.SetCurrentLength(length)?;
            let sample = MFCreateSample()?;
            sample.AddBuffer(&buffer)?;
            sample.SetSampleTime(i64::try_from(pts_us.saturating_mul(10)).unwrap_or(i64::MAX))?;
            let mut decoded = Vec::new();
            if let Err(error) = self.transform.ProcessInput(0, &sample, 0) {
                if error.code() != MF_E_NOTACCEPTING {
                    return Err(error).context("submit H.264 access unit");
                }
                self.drain_output(&mut decoded)?;
                self.transform
                    .ProcessInput(0, &sample, 0)
                    .context("retry H.264 access unit after draining decoder output")?;
            }
            self.drain_output(&mut decoded)?;
            Ok(decoded)
        }
    }

    unsafe fn drain_output(&self, decoded: &mut Vec<DecodedTexture>) -> Result<()> {
        for _ in 0..4 {
            match unsafe { self.try_output()? } {
                Some(output) => decoded.push(output),
                None => return Ok(()),
            }
        }
        Ok(())
    }

    unsafe fn try_output(&self) -> Result<Option<DecodedTexture>> {
        let mut output = MFT_OUTPUT_DATA_BUFFER::default();
        let mut status = 0;
        let result = unsafe {
            self.transform
                .ProcessOutput(0, std::slice::from_mut(&mut output), &mut status)
        };
        let events = unsafe { ManuallyDrop::take(&mut output.pEvents) };
        drop(events);
        if let Err(error) = result {
            let sample = unsafe { ManuallyDrop::take(&mut output.pSample) };
            drop(sample);
            if error.code() == MF_E_TRANSFORM_NEED_MORE_INPUT {
                return Ok(None);
            }
            return Err(error).context("receive hardware-decoded frame");
        }
        let sample = unsafe { ManuallyDrop::take(&mut output.pSample) }
            .context("hardware decoder produced no output sample")?;
        let pts_hns = unsafe { sample.GetSampleTime() }
            .context("hardware decoder output has no timestamp")?;
        let pts_us = u64::try_from(pts_hns.max(0)).unwrap_or(u64::MAX) / 10;
        let buffer = unsafe { sample.GetBufferByIndex(0) }?;
        let dxgi: IMFDXGIBuffer = buffer
            .cast()
            .context("decoder output is not a DXGI buffer")?;
        let mut raw = null_mut();
        unsafe { dxgi.GetResource(&ID3D11Texture2D::IID, &mut raw) }?;
        let texture = unsafe { ID3D11Texture2D::from_raw(raw) };
        Ok(Some(DecodedTexture {
            texture,
            subresource: unsafe { dxgi.GetSubresourceIndex() }?,
            pts_us,
        }))
    }
}

impl Drop for HardwareH264Decoder {
    fn drop(&mut self) {
        let _ = unsafe {
            self.transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0)
        };
    }
}

unsafe fn activate_hardware_decoder() -> Result<IMFTransform> {
    let input = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_H264,
    };
    let output = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_NV12,
    };
    let mut raw_activations: *mut Option<IMFActivate> = null_mut();
    let mut count = 0;
    unsafe {
        MFTEnumEx(
            MFT_CATEGORY_VIDEO_DECODER,
            MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER,
            Some(&input),
            Some(&output),
            &mut raw_activations,
            &mut count,
        )
        .context("enumerate hardware H.264 decoders")?;
    }
    if count == 0 || raw_activations.is_null() {
        bail!("no hardware H.264 decoder with NV12 D3D11 output is installed");
    }
    let mut activations = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        if let Some(activation) = unsafe { std::ptr::read(raw_activations.add(index)) } {
            activations.push(activation);
        }
    }
    unsafe { CoTaskMemFree(Some(raw_activations.cast())) };
    let activation = activations
        .into_iter()
        .next()
        .context("hardware decoder enumeration returned empty activations")?;
    unsafe { activation.ActivateObject::<IMFTransform>() }
        .context("activate hardware H.264 decoder")
}

fn video_type(subtype: windows::core::GUID, width: u32, height: u32) -> Result<IMFMediaType> {
    unsafe {
        let media_type = MFCreateMediaType()?;
        let attributes: IMFAttributes = media_type.cast()?;
        attributes.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)?;
        attributes.SetGUID(&MF_MT_SUBTYPE, &subtype)?;
        let frame_size = (u64::from(width) << 32) | u64::from(height);
        attributes.SetUINT64(&MF_MT_FRAME_SIZE, frame_size)?;
        Ok(media_type)
    }
}

struct GpuCompositor {
    width: u32,
    height: u32,
    vertex_shader: ID3D11VertexShader,
    pixel_shader: ID3D11PixelShader,
    alpha_texture: ID3D11Texture2D,
    alpha_view: ID3D11ShaderResourceView,
    output: ID3D11Texture2D,
    output_view: ID3D11RenderTargetView,
}

impl GpuCompositor {
    fn new(device: &ID3D11Device, width: u32, height: u32) -> Result<Self> {
        unsafe {
            let vertex_shader = compile_shader(device, b"vs_main\0", b"vs_5_0\0", true)?
                .0
                .context("vertex shader was not created")?;
            let pixel_shader = compile_shader(device, b"ps_main\0", b"ps_5_0\0", false)?
                .1
                .context("pixel shader was not created")?;
            let alpha_desc = D3D11_TEXTURE2D_DESC {
                Width: width,
                Height: height,
                MipLevels: 1,
                ArraySize: 1,
                Format: DXGI_FORMAT_R8_UNORM,
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                Usage: D3D11_USAGE_DEFAULT,
                BindFlags: D3D11_BIND_SHADER_RESOURCE.0 as u32,
                ..Default::default()
            };
            let mut alpha_texture = None;
            device.CreateTexture2D(&alpha_desc, None, Some(&mut alpha_texture))?;
            let alpha_texture = alpha_texture.context("create R8 alpha texture")?;
            let mut alpha_view = None;
            device.CreateShaderResourceView(&alpha_texture, None, Some(&mut alpha_view))?;

            let output_desc = D3D11_TEXTURE2D_DESC {
                Width: width,
                Height: height,
                MipLevels: 1,
                ArraySize: 1,
                Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                Usage: D3D11_USAGE_DEFAULT,
                BindFlags: (D3D11_BIND_RENDER_TARGET | D3D11_BIND_SHADER_RESOURCE).0 as u32,
                ..Default::default()
            };
            let mut output = None;
            device.CreateTexture2D(&output_desc, None, Some(&mut output))?;
            let output = output.context("create premultiplied BGRA output texture")?;
            let mut output_view = None;
            device.CreateRenderTargetView(&output, None, Some(&mut output_view))?;
            Ok(Self {
                width,
                height,
                vertex_shader,
                pixel_shader,
                alpha_texture,
                alpha_view: alpha_view.context("create R8 alpha shader view")?,
                output,
                output_view: output_view.context("create BGRA render target")?,
            })
        }
    }

    fn composite(
        &mut self,
        device: &ID3D11Device,
        context: &ID3D11DeviceContext,
        decoded: &DecodedTexture,
        alpha: &[u8],
    ) -> Result<&ID3D11Texture2D> {
        if alpha.len() != (self.width as usize).saturating_mul(self.height as usize) {
            bail!("decoded A8T1 alpha length does not match frame dimensions");
        }
        unsafe {
            context.UpdateSubresource(
                &self.alpha_texture,
                0,
                None,
                alpha.as_ptr().cast(),
                self.width,
                0,
            );
            let device3: ID3D11Device3 = device
                .cast()
                .context("D3D11.3 is required for NV12 plane views")?;
            let y_view = create_plane_view(&device3, decoded, DXGI_FORMAT_R8_UNORM, 0)?;
            let uv_view = create_plane_view(&device3, decoded, DXGI_FORMAT_R8G8_UNORM, 1)?;
            let resources = [Some(y_view), Some(uv_view), Some(self.alpha_view.clone())];
            context.PSSetShaderResources(0, Some(&resources));
            context.VSSetShader(&self.vertex_shader, None);
            context.PSSetShader(&self.pixel_shader, None);
            context.IASetPrimitiveTopology(D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
            context.RSSetViewports(Some(&[D3D11_VIEWPORT {
                Width: self.width as f32,
                Height: self.height as f32,
                MaxDepth: 1.0,
                ..Default::default()
            }]));
            context.OMSetRenderTargets(Some(&[Some(self.output_view.clone())]), None);
            context.Draw(3, 0);
            context.PSSetShaderResources(0, Some(&[None, None, None]));
            context.OMSetRenderTargets(None, None);
        }
        Ok(&self.output)
    }
}

unsafe fn create_plane_view(
    device: &ID3D11Device3,
    decoded: &DecodedTexture,
    format: windows::Win32::Graphics::Dxgi::Common::DXGI_FORMAT,
    plane: u32,
) -> Result<ID3D11ShaderResourceView> {
    let mut texture_desc = D3D11_TEXTURE2D_DESC::default();
    unsafe { decoded.texture.GetDesc(&mut texture_desc) };
    let desc = match select_plane_view_dimension(
        texture_desc.ArraySize,
        texture_desc.MipLevels,
        decoded.subresource,
    )
    .map_err(|message| anyhow!(message))?
    {
        PlaneViewDimension::Texture2D { most_detailed_mip } => D3D11_SHADER_RESOURCE_VIEW_DESC1 {
            Format: format,
            ViewDimension: windows::Win32::Graphics::Direct3D::D3D_SRV_DIMENSION_TEXTURE2D,
            Anonymous: D3D11_SHADER_RESOURCE_VIEW_DESC1_0 {
                Texture2D: D3D11_TEX2D_SRV1 {
                    MostDetailedMip: most_detailed_mip,
                    MipLevels: 1,
                    PlaneSlice: plane,
                },
            },
        },
        PlaneViewDimension::Texture2DArray {
            most_detailed_mip,
            first_array_slice,
        } => D3D11_SHADER_RESOURCE_VIEW_DESC1 {
            Format: format,
            ViewDimension: windows::Win32::Graphics::Direct3D::D3D_SRV_DIMENSION_TEXTURE2DARRAY,
            Anonymous: D3D11_SHADER_RESOURCE_VIEW_DESC1_0 {
                Texture2DArray: D3D11_TEX2D_ARRAY_SRV1 {
                    MostDetailedMip: most_detailed_mip,
                    MipLevels: 1,
                    FirstArraySlice: first_array_slice,
                    ArraySize: 1,
                    PlaneSlice: plane,
                },
            },
        },
    };
    let mut view: Option<ID3D11ShaderResourceView1> = None;
    unsafe {
        device.CreateShaderResourceView1(&decoded.texture, Some(&desc), Some(&mut view))?;
    }
    view.context("create NV12 plane shader view")?
        .cast()
        .context("cast NV12 plane shader view")
}

unsafe fn compile_shader(
    device: &ID3D11Device,
    entry: &[u8],
    target: &[u8],
    vertex: bool,
) -> Result<(Option<ID3D11VertexShader>, Option<ID3D11PixelShader>)> {
    let mut bytecode: Option<ID3DBlob> = None;
    let mut errors: Option<ID3DBlob> = None;
    unsafe {
        D3DCompile(
            SHADER.as_ptr().cast(),
            SHADER.len(),
            PCSTR::null(),
            None,
            None,
            PCSTR(entry.as_ptr()),
            PCSTR(target.as_ptr()),
            0,
            0,
            &mut bytecode,
            Some(&mut errors),
        )
    }
    .map_err(|error| {
        let detail = errors.as_ref().map_or_else(String::new, |blob| unsafe {
            let bytes = std::slice::from_raw_parts(
                blob.GetBufferPointer().cast::<u8>(),
                blob.GetBufferSize(),
            );
            String::from_utf8_lossy(bytes).into_owned()
        });
        anyhow!("compile D3D11 shader: {error}; {detail}")
    })?;
    let bytecode = bytecode.context("D3DCompile returned no bytecode")?;
    let bytes = unsafe {
        std::slice::from_raw_parts(
            bytecode.GetBufferPointer().cast::<u8>(),
            bytecode.GetBufferSize(),
        )
    };
    if vertex {
        let mut shader = None;
        unsafe { device.CreateVertexShader(bytes, None, Some(&mut shader))? };
        Ok((shader, None))
    } else {
        let mut shader = None;
        unsafe { device.CreatePixelShader(bytes, None, Some(&mut shader))? };
        Ok((None, shader))
    }
}
