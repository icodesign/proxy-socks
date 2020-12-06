#[macro_use]
extern crate log;

pub mod auth;
pub mod client;
pub mod common;
pub mod server;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
