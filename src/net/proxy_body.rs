//! 不缓存正文的大小/空闲限制；下游丢弃响应时立即取消上游驱动。
use bytes::Bytes;
use hyper::body::{Body, Frame, Incoming, SizeHint};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

pub struct Driver(pub tokio::task::AbortHandle);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
pub struct StreamBody {
    inner: Incoming,
    remaining: Option<u64>,
    timeout: Duration,
    timer: Pin<Box<tokio::time::Sleep>>,
    exceeded: Arc<AtomicBool>,
    _driver: Option<Driver>,
}
impl StreamBody {
    pub fn new(
        inner: Incoming,
        limit: Option<u64>,
        timeout: Duration,
        exceeded: Arc<AtomicBool>,
        driver: Option<Driver>,
    ) -> Self {
        Self {
            inner,
            remaining: limit,
            timeout,
            timer: Box::pin(tokio::time::sleep(timeout)),
            exceeded,
            _driver: driver,
        }
    }
}
impl Body for StreamBody {
    type Data = Bytes;
    type Error = io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, io::Error>>> {
        loop {
            match Pin::new(&mut self.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    let timeout = self.timeout;
                    self.timer
                        .as_mut()
                        .reset(tokio::time::Instant::now() + timeout);
                    if let Some(data) = frame.data_ref() {
                        if let Some(left) = self.remaining.as_mut() {
                            if data.len() as u64 > *left {
                                self.exceeded.store(true, Ordering::Relaxed);
                                return Poll::Ready(Some(Err(io::Error::other(
                                    "正文超过大小限制",
                                ))));
                            }
                            *left -= data.len() as u64;
                        }
                        return Poll::Ready(Some(Ok(frame)));
                    }
                    // 不转发未经首部策略验证的尾部字段。
                }
                Poll::Ready(Some(Err(_))) => {
                    return Poll::Ready(Some(Err(io::Error::other("流式正文读取失败"))))
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => {
                    return if self.timer.as_mut().poll(cx).is_ready() {
                        Poll::Ready(Some(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "正文空闲超时",
                        ))))
                    } else {
                        Poll::Pending
                    }
                }
            }
        }
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
