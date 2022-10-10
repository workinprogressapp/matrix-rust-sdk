
use dispatch::{Queue, QueuePriority};
use async_executor::Executor as Aexec;
use async_task::Task as Atask;
use futures_lite::future;
use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
pub struct Executor {
    queue: Queue,
    executor: Arc<Aexec<'static>>,
}

impl Default for Executor {
    fn default() -> Self {
        let me = Executor {
            queue: Queue::global(QueuePriority::Background),
            executor: Arc::new(Aexec::new()),
        };

        me.startup();
        me
    }
}

impl Executor {
    pub fn with_queue(queue: Queue) -> Self {
        let me = Executor { queue, executor: Arc::new(Aexec::new()) };
        me.startup();
        me
    }
}

impl Executor {
    pub fn block_on<F: Future>(&self, future: F) -> F::Output {
        future::block_on(self.executor.run(async { future.await }))
    }

    fn startup(&self) {
        // make this CPU threads based maybe?
        for _ in 0..=4 {
            let ex = self.executor.clone();
            self.queue.exec_async(move || {
                future::block_on(ex.run(future::pending::<()>()));
            })
        }
    }

    pub fn spawn<F>(&self, future: F) -> Task<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.executor.spawn(async { future.await } ).into()
    }

}

pub struct Task<T> {
    handle: Atask<T>
}

impl<T> Task<T> {
    pub async fn cancel(self) -> Option<T> {
        self.handle.cancel().await
    }
}

impl<T> From<Atask<T>> for Task<T> {
    fn from(handle: Atask<T>) -> Self {
        Task { handle }
    }
}

impl<T> fmt::Debug for Task<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Task").finish()
    }
}

impl<T> Future for Task<T> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.handle).poll(cx)
    }
}