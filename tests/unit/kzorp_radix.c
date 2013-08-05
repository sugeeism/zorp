/*** start test: radix ***/

struct kz_lookup_ipv6_node {
	struct kz_lookup_ipv6_node *parent;
	struct kz_lookup_ipv6_node *left;
	struct kz_lookup_ipv6_node *right;
	struct in6_addr addr;
	struct kz_zone *zone;
	__u16 prefix_len;
};

static inline struct kz_lookup_ipv6_node *
ipv6_node_new(void)
{
#ifdef __KERNEL__
	return kzalloc(sizeof(struct kz_lookup_ipv6_node), GFP_KERNEL);
#else
	return calloc(1, sizeof(struct kz_lookup_ipv6_node));
#endif
}

static inline void
ipv6_node_free(struct kz_lookup_ipv6_node *n)
{
#ifdef __KERNEL__
	kfree(n);
#else
	free(n);
#endif
}

static inline __be32
ipv6_addr_bit_set(const void *token, int bit)
{
	const __be32 *addr = token;

	return htonl(1 << ((~bit) & 0x1F)) & addr[bit >> 5];
}

struct kz_lookup_ipv6_node *ipv6_add(struct kz_lookup_ipv6_node *root, struct in6_addr *addr,
			   int prefix_len)
{
	struct kz_lookup_ipv6_node *n, *parent, *leaf, *intermediate;
	__be32 dir = 0;
	int prefix_match_len;

	n = root;

	do {
		/* prefix is different */
		if (prefix_len < n->prefix_len ||
		    !ipv6_prefix_equal(&n->addr, addr, n->prefix_len))
			goto insert_above;

		/* prefix is the same */
		if (prefix_len == n->prefix_len)
			return n;

		/* more bits to go */
		dir = ipv6_addr_bit_set(addr, n->prefix_len);
		parent = n;
		n = dir ? n->right : n->left;
	} while (n);

	/* add a new leaf node */
	leaf = ipv6_node_new();
	if (leaf == NULL)
		return NULL;

	leaf->prefix_len = prefix_len;
	leaf->parent = parent;
	ipv6_addr_copy(&leaf->addr, addr);

	if (dir)
		parent->right = leaf;
	else
		parent->left = leaf;

	return leaf;

insert_above:
	/* split node, since we have a new key with shorter or different prefix */
	parent = n->parent;

	prefix_match_len = __ipv6_addr_diff(addr, &n->addr, sizeof(*addr));

	if (prefix_len > prefix_match_len) {
		/*
		 *	   +----------------+
		 *	   |  intermediate  |
		 *	   +----------------+
		 *	      /	       	  \
		 * +--------------+  +--------------+
		 * |   new leaf	  |  |   old node   |
		 * +--------------+  +--------------+
		 */
		intermediate = ipv6_node_new();
		leaf = ipv6_node_new();
		if (leaf == NULL || intermediate == NULL) {
			if (leaf)
				ipv6_node_free(leaf);
			if (intermediate)
				ipv6_node_free(intermediate);
			return NULL;
		}

		intermediate->prefix_len = prefix_match_len;
		ipv6_addr_copy(&intermediate->addr, addr);

		if (dir)
			parent->right = intermediate;
		else
			parent->left = intermediate;

		leaf->prefix_len = prefix_len;
		ipv6_addr_copy(&leaf->addr, addr);

		intermediate->parent = parent;
		leaf->parent = intermediate;
		n->parent = intermediate;

		if (ipv6_addr_bit_set(&n->addr, prefix_match_len)) {
			intermediate->right = n;
			intermediate->left = leaf;
		} else {
			intermediate->right = leaf;
			intermediate->left = n;
		}
	} else {
		/* prefix_len <= prefix_match_len
		 *
		 *	 +-------------------+
		 *	 |     new leaf      |
		 *	 +-------------------+
		 *	    /  	       	  \
		 * +--------------+  +--------------+
		 * |   old node   |  |     NULL     |
		 * +--------------+  +--------------+
		 */
		leaf = ipv6_node_new();
		if (leaf == NULL)
			return NULL;

		leaf->prefix_len = prefix_len;
		leaf->parent = parent;
		ipv6_addr_copy(&leaf->addr, addr);

		if (dir)
			parent->right = leaf;
		else
			parent->left = leaf;

		if (ipv6_addr_bit_set(&n->addr, prefix_len))
			leaf->right = n;
		else
			leaf->left = n;

		n->parent = leaf;
	}

	return leaf;
}

static struct kz_lookup_ipv6_node *
ipv6_lookup(struct kz_lookup_ipv6_node *root, const struct in6_addr *addr)
{
	struct kz_lookup_ipv6_node *n = root;
	__be32 dir;

	/* first, descend to a possibly matching node */

	for (;;) {
		struct kz_lookup_ipv6_node *next;

		dir = ipv6_addr_bit_set(addr, n->prefix_len);

		next = dir ? n->right : n->left;

		if (next) {
			n = next;
			continue;
		}

		break;
	}

	/* we're at a node that has a possibility to match: go up the
	 * tree until we find something that is matching exactly */

	while (n) {
		if (n->zone) {
			/* this is not an intermediate node, but a
			 * real one with data associated with it */
			if (ipv6_prefix_equal(&n->addr, addr, n->prefix_len))
				return n;
		}

		n = n->parent;
	}

	return NULL;
}

static void
ipv6_destroy(struct kz_lookup_ipv6_node *node)
{
	if (node->left)
		ipv6_destroy(node->left);

	if (node->right)
		ipv6_destroy(node->right);

	ipv6_node_free(node);
}

/*** end test: radix ***/
