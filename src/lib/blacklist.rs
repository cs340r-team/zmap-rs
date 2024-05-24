// pub fn blacklist_count_allowed() -> u64 {
//     return 1u64 << 32;
// }
use blocklist::constraint;
use constraint::{Constraint, TreeNode};
use std::fs::File;
use std::io::{self, BufRead};
use std::net::Ipv4Addr;
use std::path::Path;

// fn init(file: &str, name: &str, value: i32, constraint: &mut Constraint) -> io::Result<()> {
//     let fp: File = File::open(file)?;
//     let reader: io::BufReader<File> = io::BufReader::new(fp);

//     for line in reader.lines() {
//         let line: String = line?;
//         let line: &str = line.split('#').next().unwrap_or("").trim();
//         if line.is_empty() {
//             continue;
//         }
//         let mut parts: std::str::Split<char> = line.split('/');
//         let ip: &str = parts.next().unwrap();
//         let prefix_len: i32 = parts.next().unwrap_or("32").parse::<i32>().unwrap_or(32);
//         let addr: Ipv4Addr = ip.parse::<Ipv4Addr>().unwrap();
//         constraint.set_recurse(
//             &mut constraint.root,
//             u32::from(addr).swap_bytes(),
//             prefix_len,
//             value,
//         );
//     }

//     Ok(())
// }
fn init(file: &str, name: &str, value: i32, constraint: &mut Constraint) -> io::Result<()> {
    let fp = File::open(file)?;
    let reader = io::BufReader::new(fp);

    for line in reader.lines() {
        let line = line?;
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let mut parts = line.split('/');
        let ip = parts.next().unwrap();
        let prefix_len = parts.next().unwrap_or("32").parse::<i32>().unwrap_or(32);
        let addr = ip.parse::<Ipv4Addr>().unwrap();

        // Borrow the root node separately to avoid multiple mutable borrows
        let root = &mut constraint.root;
        constraint.set_recurse(root, u32::from(addr).swap_bytes(), prefix_len, value);
    }

    Ok(())
}

fn blacklist_is_allowed(constraint: &Constraint, s_addr: u32) -> bool {
    constraint.lookup(s_addr.swap_bytes()) == 1
}

// fn blacklist_prefix(constraint: &mut Constraint, ip: &str, prefix_len: i32) {
//     let addr = ip.parse::<Ipv4Addr>().unwrap();
//     constraint.set_recurse(
//         &mut constraint.root,
//         u32::from(addr).swap_bytes(),
//         prefix_len,
//         0,
//     );
// }
fn blacklist_prefix(constraint: &mut Constraint, ip: &str, prefix_len: i32) {
    let addr: Ipv4Addr = ip.parse::<Ipv4Addr>().unwrap();
    let root: &mut Box<TreeNode> = &mut constraint.root;
    constraint.set_recurse(root, u32::from(addr).swap_bytes(), prefix_len, 0);
}

// fn whitelist_prefix(constraint: &mut Constraint, ip: &str, prefix_len: i32) {
//     let addr = ip.parse::<Ipv4Addr>().unwrap();
//     constraint.set_recurse(
//         &mut constraint.root,
//         u32::from(addr).swap_bytes(),
//         prefix_len,
//         1,
//     );
// }
fn whitelist_prefix(constraint: &mut Constraint, ip: &str, prefix_len: i32) {
    let addr: Ipv4Addr = ip.parse::<Ipv4Addr>().unwrap();
    let root: &mut Box<TreeNode> = &mut constraint.root;
    constraint.set_recurse(root, u32::from(addr).swap_bytes(), prefix_len, 1);
}

fn blacklist_count_allowed(constraint: &Constraint) -> u64 {
    constraint.count_ips(1) as u64
}

fn blacklist_count_not_allowed(constraint: &Constraint) -> u64 {
    constraint.count_ips(0) as u64
}

fn blacklist_init_from_files(
    whitelist_filename: Option<&str>,
    blacklist_filename: Option<&str>,
) -> Constraint {
    let mut constraint = if whitelist_filename.is_some() {
        let root = Box::new(TreeNode::new(0));
        Constraint::new(root)
    } else {
        let root = Box::new(TreeNode::new(1));
        Constraint::new(root)
    };

    if let Some(filename) = whitelist_filename {
        init(filename, "whitelist", 1, &mut constraint).unwrap();
    }

    if let Some(filename) = blacklist_filename {
        init(filename, "blacklist", 0, &mut constraint).unwrap();
    }

    constraint.optimize();
    let allowed = blacklist_count_allowed(&constraint);
    println!(
        "{} addresses allowed to be scanned ({:.2}% of address space)",
        allowed,
        allowed as f64 * 100.0 / (1 << 32) as f64
    );

    constraint
}

fn main() {
    let whitelist_filename: Option<&str> = Some("path/to/whitelist.txt");
    let blacklist_filename: Option<&str> = Some("path/to/blacklist.txt");
    let mut constraint: Constraint =
        blacklist_init_from_files(whitelist_filename, blacklist_filename);

    let ip: Ipv4Addr = "192.168.1.1".parse::<Ipv4Addr>().unwrap();
    if blacklist_is_allowed(&constraint, u32::from(ip)) {
        println!("IP {} is allowed", ip);
    } else {
        println!("IP {} is not allowed", ip);
    }

    blacklist_prefix(&mut constraint, "192.168.1.0", 24);
    whitelist_prefix(&mut constraint, "10.0.0.0", 8);

    println!("Allowed IP count: {}", blacklist_count_allowed(&constraint));
    println!(
        "Not allowed IP count: {}",
        blacklist_count_not_allowed(&constraint)
    );
}
