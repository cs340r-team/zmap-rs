use std::boxed::Box;
use std::vec::Vec;

struct Node {
    l: Option<Box<Node>>,
    r: Option<Box<Node>>,
    value: i32,
}

impl Node {
    fn new(value: i32) -> Self {
        Node {
            l: None,
            r: None,
            value: value,
        }
    }

    fn is_leaf(&self) -> bool {
        self.l.is_none() && self.r.is_none()
    }

    fn convert_to_leaf(&mut self) {
        if self.is_leaf() {
            return;
        }
        self.l = None;
        self.r = None;
    }
}

struct Constraint {
    root: Option<Box<Node>>,       // root node of the tree
    radix: Vec<Option<Box<Node>>>, // array of nodes for every RADIX_LENGTH prefix
    optimized: bool,               // is radix populated and up-to-date?
}

// #include <stdio.h>
// #include <stdlib.h>
// #include <stdint.h>
// #include <string.h>
// #include <errno.h>
// #include <assert.h>
// #include <sys/socket.h>
// #include <netinet/in.h>
// #include <arpa/inet.h>

// #include "../lib/constraint.h"
// #include "../lib/logger.h"

// //
// // Efficient address-space constraints  (AH 7/2013)
// //
// // This module uses a tree-based representation to efficiently
// // manipulate and query constraints on the address space to be
// // scanned.  It provides a value for every IP address, and these
// // values are applied by setting them for network prefixes.  Order
// // matters: setting a value replaces any existing value for that
// // prefix or subsets of it.  We use this to implement network
// // whitelisting and blacklisting.
// //
// // Think of setting values in this structure like painting
// // subnets with different colors.  We can paint subnets black to
// // exclude them and white to allow them.  Only the top color shows.
// // This makes for potentially very powerful constraint specifications.
// //
// // Internally, this is implemented using a binary tree, where each
// // node corresponds to a network prefix.  (E.g., the root is
// // 0.0.0.0/0, and its children, if present, are 0.0.0.0/1 and
// // 128.0.0.0/1.)  Each leaf of the tree stores the value that applies
// // to every address within the leaf's portion of the prefix space.
// //
// // As an optimization, after all values are set, we look up the
// // value or subtree for every /16 prefix and cache them as an array.
// // This lets subsequent lookups bypass the bottom half of the tree.
// //

// /*
//  * Constraint Copyright 2013 Regents of the University of Michigan
//  *
//  * Licensed under the Apache License, Version 2.0 (the "License"); you may not
//  * use this file except in compliance with the License. You may obtain a copy
//  * of the License at http://www.apache.org/licenses/LICENSE-2.0
//  */
// typedef struct node {
// 	struct node *l;
// 	struct node *r;
// 	value_t value;
// } node_t;

// // As an optimization, we precompute lookups for every prefix of this
// // length:
// #define RADIX_LENGTH 16

// struct _constraint {
// 	node_t *root;   // root node of the tree
// 	node_t **radix; // array of nodes for every RADIX_LENGTH prefix
// 	int optimized;  // is radix populated and up-to-date?
// };

// // Tree operations respect the invariant that every node that isn't a
// // leaf has exactly two children.
// #define IS_LEAF(node) ((node)->l == NULL)

// // Allocate a new leaf with the given value
// static node_t* _create_leaf(value_t value)
// {
// 	node_t *node = malloc(sizeof(node_t));
// 	assert(node);
// 	node->l = NULL;
// 	node->r = NULL;
// 	node->value = value;
// 	return node;
// }

// // Free the subtree rooted at node.
// static void _destroy_subtree(node_t *node)
// {
// 	if (node == NULL)
// 		return;
// 	_destroy_subtree(node->l);
// 	_destroy_subtree(node->r);
// 	free(node);
// }

// // Convert from an internal node to a leaf.
// static void _convert_to_leaf(node_t *node)
// {
// 	assert(node);
// 	assert(!IS_LEAF(node));
// 	_destroy_subtree(node->l);
// 	_destroy_subtree(node->r);
// 	node->l = NULL;
// 	node->r = NULL;
// }

// // Recursive function to set value for a given network prefix within
// // the tree.  (Note: prefix must be in host byte order.)
// static void _set_recurse(node_t *node, uint32_t prefix, int len, value_t value)
// {
// 	assert(node);
// 	assert(0 <= len && len <= 32);

// 	if (len == 0) {
// 		// We're at the end of the prefix; make this a leaf and set the value.
// 		if (!IS_LEAF(node)) {
// 			_convert_to_leaf(node);
// 		}
// 		node->value = value;
// 		return;
// 	}

// 	if (IS_LEAF(node)) {
// 		// We're not at the end of the prefix, but we hit a leaf.
// 		if (node->value == value) {
// 			// A larger prefix has the same value, so we're done.
// 			return;
// 		}
// 		// The larger prefix has a different value, so we need to convert it
// 		// into an internal node and continue processing on one of the leaves.
// 		node->l = _create_leaf(node->value);
// 		node->r = _create_leaf(node->value);
// 	}

// 	// We're not at the end of the prefix, and we're at an internal
// 	// node.  Recurse on the left or right subtree.
// 	if (prefix & 0x80000000) {
// 		_set_recurse(node->r, prefix << 1, len - 1, value);
// 	} else {
// 		_set_recurse(node->l, prefix << 1, len - 1, value);
// 	}

// 	// At this point, we're an internal node, and the value is set
// 	// by one of our children or its descendent.  If both children are
// 	// leaves with the same value, we can discard them and become a left.
// 	if (IS_LEAF(node->r) && IS_LEAF(node->l) && node->r->value == node->l->value) {
// 		node->value = node->l->value;
// 		_convert_to_leaf(node);
// 	}
// }

// // Set the value for a given network prefix, overwriting any existing
// // values on that prefix or subsets of it.
// // (Note: prefix must be in host byte order.)
// void constraint_set(constraint_t *con, uint32_t prefix, int len, value_t value)
// {
// 	assert(con);
// 	_set_recurse(con->root, prefix, len, value);
// 	con->optimized = 0;
// }

// // Return the value pertaining to an address, according to the tree
// // starting at given root.  (Note: address must be in host byte order.)
// static int _lookup_ip(node_t *root, uint32_t address)
// {
// 	assert(root);
// 	node_t *node = root;
// 	uint32_t mask = 0x80000000;
// 	for (;;) {
// 		if (IS_LEAF(node)) {
// 			return node->value;
// 		}
// 		if (address & mask) {
// 			node = node->r;
// 		} else {
// 			node = node->l;
// 		}
// 		mask >>= 1;
// 	}
// }

// // Return the value pertaining to an address.
// // (Note: address must be in host byte order.)
// int constraint_lookup_ip(constraint_t *con, uint32_t address)
// {
// 	assert(con);
// 	if (con->optimized) {
// 		// Use radix optimization
// 		node_t *node = con->radix[address >> (32 - RADIX_LENGTH)];
// 		if (IS_LEAF(node)) {
// 			return node->value;
// 		}
// 		return _lookup_ip(node, address << RADIX_LENGTH);
// 	} else {
// 		// Do a full lookup using the tree
// 		log_trace("constraint", "Unoptimized lookup");
// 		return _lookup_ip(con->root, address);
// 	}
// }

// // Implement count_ips by recursing on halves of the tree.  Size represents
// // the number of addresses in a prefix at the current level of the tree.
// static uint64_t _count_ips_recurse(node_t *node, value_t value, uint64_t size)
// {
// 	assert(node);
// 	if (IS_LEAF(node)) {
// 		if (node->value == value) {
// 			return size;
// 		} else {
// 			return 0;
// 		}
// 	}
// 	return _count_ips_recurse(node->l, value, size >> 1) +
// 		_count_ips_recurse(node->r, value, size >> 1);
// }

// // Return the number of addresses that have a given value.
// uint64_t constraint_count_ips(constraint_t *con, value_t value)
// {
// 	assert(con);
// 	return _count_ips_recurse(con->root, value, (uint64_t)1 << 32);
// }

// // Initialize the tree.
// // All addresses will initally have the given value.
// constraint_t* constraint_init(value_t value)
// {
// 	log_trace("constraint", "Initializing");
// 	constraint_t* con = malloc(sizeof(constraint_t));
// 	con->root = _create_leaf(value);
// 	con->radix = calloc(sizeof(node_t *), 1 << RADIX_LENGTH);
// 	assert(con->radix);
// 	con->optimized = 0;
// 	return con;
// }

// // Deinitialize and free the tree.
// void constraint_free(constraint_t *con)
// {
// 	assert(con);
// 	log_trace("constraint", "Cleaning up");
// 	_destroy_subtree(con->root);
// 	free(con->radix);
// 	free(con);
// }

// // Return a node that determines the values for the addresses with
// // the given prefix.  This is either the internal node that
// // corresponds to the end of the prefix or a leaf node that
// // encompasses the prefix. (Note: prefix must be in host byte order.)
// static node_t* _lookup_node(node_t *root, uint32_t prefix, int len)
// {
// 	assert(root);
// 	assert(0 <= len && len <= 32);

// 	node_t *node = root;
// 	uint32_t mask = 0x80000000;

// 	for (int i=0; i < len; i++) {
// 		if (IS_LEAF(node)) {
// 			return node;
// 		}
// 		if (prefix & mask) {
// 			node = node->r;
// 		} else {
// 			node = node->l;
// 		}
// 		mask >>= 1;
// 	}
// 	return node;
// }

// // After values have been set, precompute prefix lookups.
// void constraint_optimize(constraint_t *con)
// {
// 	assert(con);
// 	if (con->optimized) {
// 		return;
// 	}
// 	log_trace("constraint", "Optimizing constraints");
// 	for (uint32_t i=0; i < (1 << RADIX_LENGTH); i++) {
// 		uint32_t prefix = i << (32 - RADIX_LENGTH);
// 		con->radix[i] = _lookup_node(con->root, prefix, RADIX_LENGTH);
// 	}
// 	con->optimized = 1;
// }
