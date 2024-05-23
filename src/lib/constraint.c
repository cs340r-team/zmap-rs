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

    fn lookup_ip(&self, root: &TreeNodeRef, addr: u32) -> i32 {
        let mut mask: u32 = 0x80000000;
        let mut cur_root: Rc<RefCell<TreeNode>> = root.clone();

        loop {
            {
                let cur_node: std::cell::Ref<TreeNode> = cur_root.borrow();
                if cur_node.is_leaf() {
                    return cur_node.val;
                }

                if addr & mask != 0 {
                    if let Some(ref right) = cur_node.right {
                        cur_root = right.clone();
                    } else {
                        panic!("Right node is None");
                    }
                    //root = &root.borrow().right.clone().unwrap();
                } else {
                    if let Some(ref left) = cur_node.left {
                        cur_root = left.clone();
                    } else {
                        panic!("Left child expected but not found.");
                    }
                    //root = &root.borrow().left.clone().unwrap();
                }

                mask >>= 1;
            }
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
                return self.lookup_ip(&node, addr << 16);
            }
        } else {
            return self.lookup_ip(&self.root.clone(), addr);
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

    fn lookup_node(&self, addr: u32, len: i64) -> Rc<RefCell<TreeNode>> {
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

fn main() {
    println!("Hello, world!");
}

// pub fn insert(&mut self, val: i32) {
//     if val < self.val {
//         if let Some(left) = &mut self.left {
//             left.borrow_mut().insert(val);
//         } else {
//             self.left = Some(Rc::new(RefCell::new(TreeNode::new(val))));
//         }
//     } else {
//         if let Some(right) = &mut self.right {
//             right.borrow_mut().insert(val);
//         } else {
//             self.right = Some(Rc::new(RefCell::new(TreeNode::new(val))));
//         }
//     }
// }

// fn next(&mut self) -> Option<TreeNodeRef> {
//     self.optimize();
//     if self.radix.is_empty() {
//         return None;
//     }
//     let node = self.radix.pop().unwrap();
//     let mut next = node.borrow().right.clone();
//     while let Some(next_node) = next {
//         self.radix.push(next_node.clone());
//         next = next_node.borrow().left.clone();
//     }
//     Some(node)
// }
