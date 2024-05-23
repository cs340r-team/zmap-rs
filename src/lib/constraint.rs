#[derive(Debug)]
pub struct TreeNode {
    val: i32,
    left: Option<Box<TreeNode>>,
    right: Option<Box<TreeNode>>,
}

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
    root: Box<TreeNode>,
    radix: Vec<Box<TreeNode>>,
    optimized: bool,
}

impl Constraint {
    fn new(root: Box<TreeNode>) -> Self {
        Constraint {
            root,
            radix: vec![],
            optimized: false,
        }
    }

    fn set_recurse(&mut self, node: &mut Box<TreeNode>, prefix: u32, len: i32, value: i32) {
        if len == 0 {
            if let Some(ref mut left) = node.left {
                left.convert_to_leaf();
            }
            node.val = value;
            return;
        }

        if node.is_leaf() {
            if node.val == value {
                return;
            }
            node.convert_to_leaf();
            node.left = Some(Box::new(TreeNode::new(node.val)));
            node.right = Some(Box::new(TreeNode::new(node.val)));
        }

        if prefix & 0x80000000 != 0 {
            if let Some(ref mut right) = node.right {
                self.set_recurse(right, prefix << 1, len - 1, value);
            }
        } else {
            if let Some(ref mut left) = node.left {
                self.set_recurse(left, prefix << 1, len - 1, value);
            }
        }

        if node.left.as_ref().unwrap().is_leaf()
            && node.right.as_ref().unwrap().is_leaf()
            && node.left.as_ref().unwrap().val == node.right.as_ref().unwrap().val
        {
            node.val = node.left.as_ref().unwrap().val;
            node.convert_to_leaf();
        }
    }

    fn lookup_ip(&self, node: &Box<TreeNode>, addr: u32) -> i32 {
        let mut mask: u32 = 0x80000000;
        let mut cur_node: &Box<TreeNode> = node;
        loop {
            if cur_node.is_leaf() {
                return cur_node.val;
            }
            let next = if addr & mask != 0 {
                &cur_node.right
            } else {
                &cur_node.left
            };
            match next {
                Some(ref next_node) => {
                    cur_node = next_node;
                }
                None => {
                    panic!("Node for {} is null!", addr);
                }
            }
            mask >>= 1;
            if mask == 0 {
                return 0;
            }
        }
    }

    fn lookup(&self, addr: u32) -> i32 {
        if self.optimized {
            let index: usize = (addr >> (32 - 16)) as usize;
            let node = &self.radix[index];
            if node.is_leaf() {
                return node.val;
            } else {
                return self.lookup_ip(node, addr << 16);
            }
        } else {
            return self.lookup_ip(&self.root, addr);
        }
    }

    fn count_ips_recurse(&self, node: &Box<TreeNode>, value: i32, size: i64) -> i64 {
        if node.is_leaf() {
            return size;
        }

        if node.val == value {
            return size;
        }

        return self.count_ips_recurse(node.left.as_ref().unwrap(), value, size >> 1)
            + self.count_ips_recurse(node.right.as_ref().unwrap(), value, size >> 1);
    }

    fn count_ips(&self, value: i32) -> i64 {
        return self.count_ips_recurse(&self.root, value, 1 << 32);
    }

    // fn optimize(&mut self) {
    //     if self.optimized {
    //         return;
    //     }
    //     self.optimized = true;
    //     let mut node = &self.root;
    //     while let Some(ref left) = node.left {
    //         node = left;
    //     }
    //     self.radix.push(node.clone());
    //     while let Some(ref right) = node.right {
    //         node = right;
    //         self.radix.push(node.clone());
    //     }
    // }

    fn lookup_node(&self, addr: u32, len: i64) -> &Box<TreeNode> {
        let mut node = &self.root;
        let mut mask: u32 = 0x80000000;
        for _ in 0..len {
            if node.is_leaf() {
                return node;
            }
            if addr & mask != 0 {
                if let Some(ref right) = node.right {
                    node = right;
                }
            } else {
                if let Some(ref left) = node.left {
                    node = left;
                }
            }
            mask >>= 1;
        }
        return node;
    }
}