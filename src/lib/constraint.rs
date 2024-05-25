use core::panic;
use std::{cell::RefCell, ops::Index, rc::Rc};

use log::debug;

#[derive(Debug, Clone)]
pub struct TreeNode {
    val: i32,
    left: Option<TreeNodeRef>,
    right: Option<TreeNodeRef>,
}

type TreeNodeRef = Rc<RefCell<TreeNode>>;

impl TreeNode {
    pub fn new(val: i32) -> Self {
        TreeNode {
            val,
            left: None,
            right: None,
        }
    }

    fn is_leaf(&self) -> bool {
        self.left.is_none() && self.right.is_none()
    }

    fn convert_to_leaf(&mut self) {
        if self.is_leaf() {
            return;
        }
        self.left = None;
        self.right = None;
    }
}

#[derive(Clone)]
pub struct Constraint {
    pub root: TreeNodeRef,
    pub radix: Vec<TreeNodeRef>,
    pub optimized: bool,
}

impl Constraint {
    const RADIX_LENGTH: u32 = 16;

    pub fn new(root: TreeNodeRef) -> Self {
        Constraint {
            root,
            radix: vec![],
            optimized: false,
        }
    }

    pub fn lookup_ip(&self, node: &TreeNodeRef, addr: u32) -> i32 {
        if node.borrow().is_leaf() {
            return node.borrow().val;
        }

        if addr & (1 << 31) != 0 {
            return self.lookup_ip(node.borrow().right.as_ref().unwrap(), addr << 1);
        }
        return self.lookup_ip(node.borrow().left.as_ref().unwrap(), addr << 1);
    }

    pub fn lookup(&self, addr: u32) -> i32 {
        if self.optimized {
            let index: usize = (addr as u64 >> (32 - Constraint::RADIX_LENGTH)) as usize;
            let node = &self.radix[index];
            if node.borrow().is_leaf() {
                return node.borrow().val;
            } else {
                return self.lookup_ip(node, addr << Constraint::RADIX_LENGTH);
            }
        } else {
            debug!("Unoptimized constraint lookup");
            return self.lookup_ip(&self.root, addr);
        }
    }

    pub fn count_ips_recurse(&self, node: &TreeNodeRef, value: i32, size: u64) -> u64 {
        if node.borrow().is_leaf() {
            if node.borrow().val == value {
                return size;
            } else {
                return 0;
            }
        }

        return self.count_ips_recurse(node.borrow().left.as_ref().unwrap(), value, size >> 1)
            + self.count_ips_recurse(node.borrow().right.as_ref().unwrap(), value, size >> 1);
    }

    pub fn count_ips(&self, value: i32) -> u64 {
        return self.count_ips_recurse(&self.root, value, 1u64 << 32);
    }

    pub fn optimize(&mut self) {
        if self.optimized {
            return;
        }
        self.optimized = true;

        for i in 0..(1u64 << Constraint::RADIX_LENGTH) {
            let prefix = i << (32 - Constraint::RADIX_LENGTH);
            let node = self.lookup_node(&self.root, prefix as u32);
            self.radix.push(node.clone());
        }
    }

    pub fn lookup_node(&self, node: &TreeNodeRef, addr: u32) -> TreeNodeRef {
        if node.borrow().is_leaf() {
            return node.clone();
        }

        if addr & (1 << 31) != 0 {
            return self.lookup_node(node.borrow().right.as_ref().unwrap(), addr << 1);
        }

        return self.lookup_node(node.borrow().left.as_ref().unwrap(), addr << 1);
    }
}

pub fn set_recurse(node: &TreeNodeRef, prefix: u32, len: i32, value: i32) {
    if len == 0 {
        if !node.borrow().is_leaf() {
            node.borrow_mut().convert_to_leaf();
        }
        node.borrow_mut().val = value;
        return;
    }

    if node.borrow().is_leaf() {
        let node_value = node.borrow().val;
        if node_value == value {
            return;
        }

        let mut node_borrow_mut = node.borrow_mut();
        node_borrow_mut.left = Some(Rc::new(RefCell::new(TreeNode::new(node_value))));
        node_borrow_mut.right = Some(Rc::new(RefCell::new(TreeNode::new(node_value))));
    }

    let node_borrow = node.borrow();

    if prefix & (1 << 31) != 0 {
        set_recurse(
            node_borrow.right.as_ref().unwrap(),
            prefix << 1,
            len - 1,
            value,
        );
    } else {
        set_recurse(
            node_borrow.left.as_ref().unwrap(),
            prefix << 1,
            len - 1,
            value,
        );
    }

    let left = node_borrow.left.as_ref().unwrap().borrow();
    let right = node_borrow.right.as_ref().unwrap().borrow();
    if left.is_leaf() && right.is_leaf() && left.val == right.val {
        let mut node_borrow_mut = node.borrow_mut();
        node_borrow_mut.val = left.val;
        node_borrow_mut.convert_to_leaf();
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const ADDR_DISALLOWED: i32 = 0;
    const ADDR_ALLOWED: i32 = 1;

    #[test]
    fn test_constraint() {
        let mut root = Rc::new(RefCell::new(TreeNode::new(ADDR_DISALLOWED)));
        let mut constraint = Constraint::new(root);

        let ip1 = Ipv4Addr::new(0, 0, 0, 0);
        set_recurse(&mut constraint.root, ip1.into(), 8, ADDR_ALLOWED);

        let count = constraint.count_ips(ADDR_ALLOWED);
        assert_eq!(count, 1 << 24);

        let ip2 = Ipv4Addr::new(192, 168, 1, 1);
        set_recurse(&mut constraint.root, ip2.into(), 32, ADDR_DISALLOWED);

        constraint.optimize();

        let count = constraint.count_ips(ADDR_DISALLOWED);
        assert_eq!(count, (1u64 << 32) - (1 << 24));

        assert!(constraint.lookup(ip1.into()) == ADDR_ALLOWED);
        assert!(constraint.lookup(ip2.into()) == ADDR_DISALLOWED);
    }
}
