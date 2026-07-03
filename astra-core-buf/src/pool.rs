use std::cell::RefCell;

const POOL_SIZE: usize = 8192;

thread_local! {
    static BUF_POOL: RefCell<Vec<Box<[u8; POOL_SIZE]>>> = const { RefCell::new(Vec::new()) };
}

pub fn alloc() -> Box<[u8; POOL_SIZE]> {
    BUF_POOL.with(|pool| {
        pool.borrow_mut()
            .pop()
            .unwrap_or_else(|| Box::new([0u8; POOL_SIZE]))
    })
}

pub fn release(buf: Box<[u8; POOL_SIZE]>) {
    BUF_POOL.with(|pool| {
        let mut pool = pool.borrow_mut();
        if pool.len() < 1024 {
            pool.push(buf);
        }
    });
}
