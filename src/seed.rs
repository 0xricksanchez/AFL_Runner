// Arbitrary value used for an initial entropy to seed our PRNG.
const ENTROPY: u64 = 0x5fd8_9eda_3130_256d;

#[derive(Debug, Clone, Copy)]
pub struct Xorshift64 {
    state: u64,
}

impl Xorshift64 {
    pub fn new(seed: u64) -> Self {
        Self {
            state: ENTROPY ^ seed,
        }
    }

    pub fn next(&mut self) -> u64 {
        let x = self.state;
        self.state ^= self.state << 13;
        self.state ^= self.state >> 17;
        self.state ^= self.state << 43;
        x
    }
}
