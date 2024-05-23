// use std::boxed::Box;
// use std::vec::Vec;

// struct Node {
//     l: Option<Box<Node>>,
//     r: Option<Box<Node>>,
//     value: i32,
// }

// impl Node {
//     fn new(value: i32) -> Self {
//         Self {
//             l: None,
//             r: None,
//             value,
//         }
//     }

//     fn is_leaf(&self) -> bool {
//         self.l.is_none() && self.r.is_none()
//     }

//     fn convert_to_leaf(&mut self) {
//         if self.is_leaf() {
//             return;
//         }
//         self.l = None;
//         self.r = None;
//     }
// }

// struct Constraint {
//     root: Option<Box<Node>>,       // root node of the tree
//     radix: Vec<Option<Box<Node>>>, // array of nodes for every RADIX_LENGTH prefix
//     optimized: bool,               // is radix populated and up-to-date?
// }

// impl Constraint {
//     fn new(value: i32) -> Self {
//         let root = Some(Box::new(Node::new(value)));
//         let radix = vec![None; (u16::MAX + 1) as usize];
//         Constraint {
//             root,
//             radix,
//             optimized: false,
//         }
//     }
// }

