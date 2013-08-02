/*** start test: mask ***/

/**
 * mask_to_size_v4 - given a 32 bit IPv4 subnet mask return how many leading 1 bits are set
 * @mask: IPv4 subnet mask
 *
 * Returns: the number of leading '1' bits in @mask
 */
static inline unsigned int
mask_to_size_v4(const struct in_addr * const mask)
{
	if (mask == 0U)
		return 0;
	else
		return 32 - fls(ntohl(~mask->s_addr));
}

/**
 * mask_to_size_v6 - given a 128 bit IPv6 subnet mask return how many leading 1 bits are set
 * @mask: IPv6 subnet mask
 *
 * Returns: the number of leading '1' bits in @mask
 */
static inline unsigned int
mask_to_size_v6(const struct in6_addr * const mask)
{
	unsigned int i;

	if (mask->s6_addr32[0] == 0U &&
	    mask->s6_addr32[1] == 0U &&
	    mask->s6_addr32[2] == 0U &&
	    mask->s6_addr32[3] == 0U)
		return 0;

	for (i = 0; i < 4; i++) {
		u_int32_t m = mask->s6_addr32[i];
		if (m == 0xffffffff)
			continue;
		if (m == 0)
			return i * 32;

		return i * 32 + 32 - fls(ntohl(~m));
	}

	return 128;
}

/*** end test: mask ***/
