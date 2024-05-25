use log::debug;

use super::constraint::{set_recurse, Constraint, TreeNode};
use std::cell::RefCell;
use std::fs::File;
use std::io::{self, BufRead};
use std::net::Ipv4Addr;
use std::rc::Rc;

fn init(file: &str, value: i32, constraint: &mut Constraint) -> io::Result<()> {
    let fp: File = File::open(file)?;
    let reader: io::BufReader<File> = io::BufReader::new(fp);

    for line in reader.lines() {
        let line: String = line?;
        let line: &str = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts: std::str::Split<char> = line.split('/');
        let ip = parts.next().unwrap();
        let prefix_len: i32 = parts.next().unwrap_or("32").parse::<i32>().unwrap_or(32);
        let addr: Ipv4Addr = ip.parse::<Ipv4Addr>().unwrap();

        // Borrow the root node separately to avoid multiple mutable borrows
        let root = &mut constraint.root;
        set_recurse(root, u32::from(addr), prefix_len, value);
    }

    Ok(())
}

#[derive(Clone)]
pub struct Blacklist {
    constraint: Constraint,
}

impl Blacklist {
    const ADDR_DISALLOWED: i32 = 0;
    const ADDR_ALLOWED: i32 = 1;

    pub fn new(whitelist_filename: Option<String>, blacklist_filename: Option<String>) -> Self {
        let mut constraint = if whitelist_filename.is_some() {
            let root = Rc::new(RefCell::new(TreeNode::new(0)));
            Constraint::new(root)
        } else {
            let root = Rc::new(RefCell::new(TreeNode::new(1)));
            Constraint::new(root)
        };

        if let Some(filename) = whitelist_filename {
            init(&filename, Blacklist::ADDR_ALLOWED, &mut constraint).unwrap();
        }

        if let Some(filename) = blacklist_filename {
            init(&filename, Blacklist::ADDR_DISALLOWED, &mut constraint).unwrap();
        }

        constraint.optimize();
        let allowed = constraint.count_ips(Blacklist::ADDR_ALLOWED);
        debug!(
            "Constructed blacklist with {} addresses allowed to be scanned ({:.2}% of address space)",
            allowed,
            allowed as f64 * 100.0 / (1u64 << 32) as f64
        );

        Self { constraint }
    }

    pub fn count_allowed(&self) -> u64 {
        self.constraint.count_ips(Blacklist::ADDR_ALLOWED)
    }

    pub fn count_not_allowed(&self) -> u64 {
        self.constraint.count_ips(Blacklist::ADDR_DISALLOWED)
    }

    pub fn is_allowed(&self, s_addr: Ipv4Addr) -> bool {
        self.constraint.lookup(s_addr.into()) == Blacklist::ADDR_ALLOWED
    }

    pub fn blacklist_prefix(&mut self, prefix: Ipv4Addr, prefix_len: i32) {
        let root = &mut self.constraint.root;
        set_recurse(root, prefix.into(), prefix_len, Blacklist::ADDR_DISALLOWED);
        self.constraint.optimized = false;
    }

    pub fn whitelist_prefix(&mut self, prefix: Ipv4Addr, prefix_len: i32) {
        let root = &mut self.constraint.root;
        set_recurse(root, prefix.into(), prefix_len, Blacklist::ADDR_ALLOWED);
        self.constraint.optimized = false;
    }
}
