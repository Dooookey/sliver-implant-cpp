/* src/platform/win32/screenshot.c - screen capture encoded as PNG via WIC. */
#include "sliver/screenshot.h"

#include <windows.h>
#include <wincodec.h>

#include <stdlib.h>
#include <string.h>

/* Copies the whole HGLOBAL stream into a malloc'ed buffer. */
static int drain_stream(IStream *stream, uint8_t **out, size_t *out_len) {
  STATSTG stat;
  LARGE_INTEGER zero;
  HGLOBAL mem;
  uint8_t *locked;
  ULONG got = 0;

  if (stream == NULL) {
    return -1;
  }
  if (FAILED(stream->lpVtbl->Stat(stream, &stat, STATFLAG_NONAME))) {
    return -1;
  }
  if (stat.cbSize.QuadPart == 0 || stat.cbSize.QuadPart > (32u * 1024u * 1024u)) {
    return -1;
  }
  if (FAILED(GetHGlobalFromStream(stream, &mem))) {
    return -1;
  }
  locked = (uint8_t *)GlobalLock(mem);
  if (locked == NULL) {
    return -1;
  }
  zero.QuadPart = 0;
  (void)stream->lpVtbl->Seek(stream, zero, STREAM_SEEK_SET, NULL);
  if (FAILED(stream->lpVtbl->Read(stream, locked, (ULONG)stat.cbSize.QuadPart, &got)) || got == 0) {
    GlobalUnlock(mem);
    return -1;
  }
  *out = (uint8_t *)malloc(got);
  if (*out == NULL) {
    GlobalUnlock(mem);
    return -1;
  }
  memcpy(*out, locked, got);
  GlobalUnlock(mem);
  *out_len = (size_t)got;
  return 0;
}

int sliver_screenshot_capture(uint8_t **out, size_t *out_len) {
  IWICImagingFactory *factory = NULL;
  IWICBitmap *wic_bitmap = NULL;
  IWICBitmapEncoder *encoder = NULL;
  IWICBitmapFrameEncode *frame = NULL;
  IPropertyBag2 *props = NULL;
  IStream *stream = NULL;
  HDC screen = NULL;
  HDC mem_dc = NULL;
  HBITMAP bitmap = NULL;
  HGDIOBJ old = NULL;
  int width;
  int height;
  int rc = -1;
  HRESULT hr;

  if (out == NULL || out_len == NULL) {
    return -1;
  }
  *out = NULL;
  *out_len = 0;

  width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
  height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
  if (width <= 0 || height <= 0) {
    width = GetSystemMetrics(SM_CXSCREEN);
    height = GetSystemMetrics(SM_CYSCREEN);
  }
  if (width <= 0 || height <= 0) {
    return -1;
  }

  hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
  if (FAILED(hr) && hr != RPC_E_CHANGED_MODE) {
    return -1;
  }
  hr = CoCreateInstance(&CLSID_WICImagingFactory, NULL, CLSCTX_INPROC_SERVER,
                        &IID_IWICImagingFactory, (void **)&factory);
  if (FAILED(hr)) {
    CoUninitialize();
    return -1;
  }

  screen = GetDC(NULL);
  mem_dc = CreateCompatibleDC(screen);
  bitmap = CreateCompatibleBitmap(screen, width, height);
  if (screen == NULL || mem_dc == NULL || bitmap == NULL) {
    goto cleanup;
  }
  old = SelectObject(mem_dc, bitmap);
  if (!BitBlt(mem_dc, 0, 0, width, height, screen, GetSystemMetrics(SM_XVIRTUALSCREEN),
              GetSystemMetrics(SM_YVIRTUALSCREEN), SRCCOPY)) {
    goto cleanup;
  }
  if (FAILED(factory->lpVtbl->CreateBitmapFromHBITMAP(factory, bitmap, NULL, WICBitmapIgnoreAlpha,
                                                      &wic_bitmap))) {
    goto cleanup;
  }
  if (FAILED(CreateStreamOnHGlobal(NULL, TRUE, &stream))) {
    goto cleanup;
  }
  if (FAILED(factory->lpVtbl->CreateEncoder(factory, &GUID_ContainerFormatPng, NULL, &encoder))) {
    goto cleanup;
  }
  if (FAILED(encoder->lpVtbl->Initialize(encoder, stream, WICBitmapEncoderNoCache))) {
    goto cleanup;
  }
  if (FAILED(encoder->lpVtbl->CreateNewFrame(encoder, &frame, &props))) {
    goto cleanup;
  }
  if (FAILED(frame->lpVtbl->Initialize(frame, props))) {
    goto cleanup;
  }
  {
    WICPixelFormatGUID format = GUID_WICPixelFormat24bppBGR;
    if (FAILED(frame->lpVtbl->SetPixelFormat(frame, &format))) {
      goto cleanup;
    }
  }
  if (FAILED(frame->lpVtbl->WriteSource(frame, (IWICBitmapSource *)wic_bitmap, NULL))) {
    goto cleanup;
  }
  if (FAILED(frame->lpVtbl->Commit(frame))) {
    goto cleanup;
  }
  if (FAILED(encoder->lpVtbl->Commit(encoder))) {
    goto cleanup;
  }
  rc = drain_stream(stream, out, out_len);

cleanup:
  if (props != NULL) props->lpVtbl->Release(props);
  if (frame != NULL) frame->lpVtbl->Release(frame);
  if (encoder != NULL) encoder->lpVtbl->Release(encoder);
  if (stream != NULL) stream->lpVtbl->Release(stream);
  if (wic_bitmap != NULL) wic_bitmap->lpVtbl->Release(wic_bitmap);
  if (factory != NULL) factory->lpVtbl->Release(factory);
  if (old != NULL && mem_dc != NULL) SelectObject(mem_dc, old);
  if (bitmap != NULL) DeleteObject(bitmap);
  if (mem_dc != NULL) DeleteDC(mem_dc);
  if (screen != NULL) ReleaseDC(NULL, screen);
  CoUninitialize();
  return rc;
}

