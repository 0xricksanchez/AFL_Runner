#[derive(Debug, Clone)]
pub struct LogRingBuffer<T> {
    buffer: Vec<T>,
    capacity: usize,
    head: usize,
    tail: usize,
    count: usize,
}

impl<T> LogRingBuffer<T> {
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: Vec::with_capacity(capacity),
            capacity,
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    pub fn append(&mut self, item: T) {
        if self.count == self.capacity {
            // Buffer is full, remove the oldest entry
            self.buffer[self.tail] = item;
            self.tail = (self.tail + 1) % self.capacity;
            self.head = (self.head + 1) % self.capacity;
        } else {
            // Buffer has space, append the new entry
            if self.count == self.buffer.len() {
                self.buffer.push(item);
            } else {
                self.buffer[self.head] = item;
            }
            self.head = (self.head + 1) % self.capacity;
            self.count += 1;
        }
    }

    pub fn join(&self, sep: &str, reverse: bool) -> String
    where
        T: std::fmt::Display,
    {
        let mut result = String::new();

        if reverse {
            for i in (0..self.count).rev() {
                let index = (self.tail + i) % self.capacity;
                let item = &self.buffer[index];
                result.push_str(&item.to_string());
                if i > 0 {
                    result.push_str(sep);
                }
            }
        } else {
            for i in 0..self.count {
                let index = (self.tail + i) % self.capacity;
                let item = &self.buffer[index];
                result.push_str(&item.to_string());
                if i < self.count - 1 {
                    result.push_str(sep);
                }
            }
        }

        result
    }

    pub fn push(&mut self, item: T) {
        self.append(item);
    }
}
