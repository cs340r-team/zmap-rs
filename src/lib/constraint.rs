use core::panic;
use std::{cell::RefCell, ops::Index, rc::Rc};

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

struct Constraint {
    root: TreeNodeRef,
    radix: Vec<TreeNodeRef>,
    optimized: bool,
}

impl Constraint {
    fn new(root: TreeNodeRef) -> Self {
        Constraint {
            root,
            radix: vec![],
            optimized: false,
        }
    }

    fn set_recurse(&mut self, node: TreeNodeRef, prefix: u32, len: i32, value: i32) {
        if len == 0 {
            // if !is_leaf(node) {
            //     node.borrow_mut().convert_to_leaf();
            // }
            //node.borrow_mut().val = value;

            if let Some(node) = node.borrow_mut().left.clone() {
                node.borrow_mut().convert_to_leaf();
            }

            node.borrow_mut().val = value;
            return;
        }

        if node.borrow().is_leaf() {
            if node.borrow().val == value {
                return;
            }
            node.borrow_mut().convert_to_leaf();
            node.borrow_mut().left = Some(Rc::new(RefCell::new(TreeNode::new(node.borrow().val))));
            node.borrow_mut().right = Some(Rc::new(RefCell::new(TreeNode::new(node.borrow().val))));
        }

        if prefix & 0x80000000 != 0 {
            self.set_recurse(
                node.borrow().right.clone().unwrap(),
                prefix << 1,
                len - 1,
                value,
            );
        } else {
            self.set_recurse(
                node.borrow().left.clone().unwrap(),
                prefix << 1,
                len - 1,
                value,
            );
        }

        if node.borrow().left.clone().unwrap().borrow().is_leaf()
            && node.borrow().right.clone().unwrap().borrow().is_leaf()
            && node.borrow().left.clone().unwrap().borrow().val
                == node.borrow().right.clone().unwrap().borrow().val
        {
            node.borrow_mut().val = node.borrow().left.clone().unwrap().borrow().val;
            node.borrow_mut().convert_to_leaf();
        }
    }

    // fn set(&mut self, key: i32, value: i32) {
    //     self.set_recurse(self.root.clone(), 0x80000000, 31, value);
    // }

    fn lookup_ip(&self, &root: TreeNodeRef, addr: u32) -> i32 {
        let mask: u32 = 0x80000000;

        loop {
            if root.borrow().is_leaf() {
                return root.borrow().val;
            }

            if addr & mask != 0 {
                root = root.borrow().right.clone().unwrap();
            } else {
                root = root.borrow().left.clone().unwrap();
            }

            mask >>= 1;
        }

        // if addr & 0x80000000 != 0 {
        //     //node = node->r;
        //     node.borrow_mut() = node.borrow().right.clone().unwrap();
        // } else {
        //     node.borrow_mut() = node.borrow().left.clone().unwrap();
        // }
    }

    fn lookup(&self, addr: u32) -> i32 {
        if self.optimized {
            let index: usize = (addr >> (32 - 16)) as usize;
            let node: <Vec<Rc<RefCell<TreeNode>>> as Index<usize>>::Output = self.radix[index];

            if node.borrow().is_leaf() {
                return node.borrow().val;
            } else {
                return self.lookup_ip(node, addr << 16);
            }
        } else {
            return self.lookup_ip(self.root.clone(), addr);
        }
        // else {
        //     if let Some(ref root) = self.root {
        //         return self.lookup_ip(node, addr);
        //     } else {
        //         panic!("Root node is None");
        //     }
        // }
    }

    fn count_ips_recurse(&self, node: TreeNodeRef, value: i32, size: i64) -> i64 {
        if node.borrow().is_leaf() {
            return size;
        }

        if node.borrow().val == value {
            return size;
        } else {
            return 0;
        }

        return self.count_ips_recurse(node.borrow().left.clone().unwrap(), value, size >> 1)
            + self.count_ips_recurse(node.borrow().right.clone().unwrap(), value, size >> 1);
    }

    fn count_ips(&self, value: i32) -> i64 {
        return self.count_ips_recurse(self.root.clone(), value, 1 << 32);
    }

    fn optimize(&mut self) {
        if self.optimized {
            return;
        }
        self.optimized = true;
        let mut node: Rc<RefCell<TreeNode>> = self.root.clone();
        while let Some(next) = node.borrow().left.clone() {
            node = next;
        }
        self.radix.push(node.clone());
        while let Some(next) = node.borrow().right.clone() {
            node = next;
            self.radix.push(node.clone());
        }
    }

    fn lookup_node(&self, addr: u32, int: len) {
        let mut node: Rc<RefCell<TreeNode>> = self.root.clone();
        let mut mask: u32 = 0x80000000;
        for _ in 0..len {
            if node.borrow().is_leaf() {
                return node;
            }
            if addr & mask != 0 {
                node = node.borrow().right.clone().unwrap();
            } else {
                node = node.borrow().left.clone().unwrap();
            }
            mask >>= 1;
        }
        return node;
    }
}