use tokio::{runtime::Runtime as TokioRuntime, task::JoinHandle};
use core::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
pub struct Executor(TokioRuntime);

impl Default for Executor {
    fn default() -> Self {
        Executor(TokioRuntime::new().expect("Could not start tokio runtime"))
    }
}

impl Executor {
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        self.0.block_on(future)
    }

    pub fn spawn<F>(&self, future: F) -> Task<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.0.spawn(future).into()
    }

    pub async fn spawn_blocking<F, R> (&self, future: F ) -> R
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        let handle = self.0.spawn_blocking(future);
        self.0.block_on(handle).unwrap()
    }
}

pub struct Task<T> {
    handle: JoinHandle<T>
}

impl<T> Task<T> {
    pub async fn cancel(self) -> Option<T> {
        self.handle.abort();
        self.handle.await.ok()
    }
}

impl<T> From<JoinHandle<T>> for Task<T> {
    fn from(handle: JoinHandle<T>) -> Self {
        Task { handle }
    }
}

impl<T> fmt::Debug for Task<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Task").finish()
    }
}

impl<T> Future for Task<T> {
    type Output = Result<T, tokio::task::JoinError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.handle).poll(cx)
    }
}