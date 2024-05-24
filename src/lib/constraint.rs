use log::debug;

#[derive(Debug, Clone)]
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

    pub fn is_leaf(&self) -> bool {
        self.left.is_none() && self.right.is_none()
    }

    pub fn convert_to_leaf(&mut self) {
        if self.is_leaf() {
            return;
        }
        self.left = None;
        self.right = None;
    }
}

#[derive(Clone)]
pub struct Constraint {
    pub root: Box<TreeNode>,
    pub radix: Vec<Box<TreeNode>>,
    pub optimized: bool,
}

impl Constraint {
    const RADIX_LENGTH: u32 = 0;

    pub fn new(root: Box<TreeNode>) -> Self {
        Constraint {
            root,
            radix: vec![],
            optimized: false,
        }
    }

    pub fn lookup_ip(&self, node: &Box<TreeNode>, addr: u32) -> i32 {
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
        }
    }

    pub fn lookup(&self, addr: u32) -> i32 {
        if self.optimized {
            let index: usize = (addr as u64 >> (32 - Constraint::RADIX_LENGTH)) as usize;
            let node = &self.radix[index];
            if node.is_leaf() {
                return node.val;
            } else {
                return self.lookup_ip(node, addr << Constraint::RADIX_LENGTH);
            }
        } else {
            debug!("Constraint unoptimized lookup");
            return self.lookup_ip(&self.root, addr);
        }
    }

    pub fn count_ips_recurse(&self, node: &Box<TreeNode>, value: i32, size: u64) -> u64 {
        if node.is_leaf() {
            if node.val == value {
                return size;
            } else {
                return 0;
            }
        }

        return self.count_ips_recurse(node.left.as_ref().unwrap(), value, size >> 1)
            + self.count_ips_recurse(node.right.as_ref().unwrap(), value, size >> 1);
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
            let node = self.lookup_node(prefix as u32, Constraint::RADIX_LENGTH.into());
            self.radix.push(node.clone());
        }
    }

    pub fn lookup_node(&self, addr: u32, len: i64) -> &Box<TreeNode> {
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

pub fn set_recurse(node: &mut Box<TreeNode>, prefix: u32, len: i32, value: i32) {
    if len == 0 {
        if !node.is_leaf() {
            node.convert_to_leaf();
        }
        node.val = value;
        return;
    }

    if node.is_leaf() {
        if node.val == value {
            return;
        }
        node.left = Some(Box::new(TreeNode::new(node.val)));
        node.right = Some(Box::new(TreeNode::new(node.val)));
    }

    if prefix & 0x80000000 != 0 {
        if let Some(ref mut right) = node.right {
            set_recurse(right, prefix << 1, len - 1, value);
        }
    } else {
        if let Some(ref mut left) = node.left {
            set_recurse(left, prefix << 1, len - 1, value);
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
