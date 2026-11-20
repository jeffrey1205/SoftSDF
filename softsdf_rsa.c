/*
 *  softsdf_rsa.c - self-contained RSA for the SoftSDF simulator.
 *
 *  GmSSL provides no RSA primitives, so this file implements a small
 *  schoolbook bignum (32-bit limbs), Miller-Rabin prime generation and
 *  RFC 8017 PKCS#1 v1.5 encryption padding. Test-simulator only: no
 *  side-channel countermeasures.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif
#include <gmssl/mem.h>
#include <gmssl/rand.h>
#include "softsdf_rsa.h"

_Static_assert(sizeof(RSArefPrivateKey) == 1412, "RSArefPrivateKey must be packed 1412 bytes");
_Static_assert(sizeof(RSArefPublicKey) == 516, "RSArefPublicKey must be packed 516 bytes");

#define BN_LIMBS	64	/* 2048-bit modulus */
#define BN_LIMBS2	128	/* full product of two moduli-sized numbers */

typedef struct {
	uint32_t w[BN_LIMBS];
	int n;			/* significant limbs, little-endian limbs */
} bn;

static void bn_zero(bn *a)
{
	memset(a, 0, sizeof(*a));
}

static void bn_set_u32(bn *a, uint32_t v)
{
	bn_zero(a);
	a->w[0] = v;
	a->n = v ? 1 : 0;
}

static void bn_trim(bn *a)
{
	while (a->n > 0 && a->w[a->n - 1] == 0)
		a->n--;
}

static int bn_clz32(uint32_t x)
{
	int n = 0;
	if (x == 0)
		return 32;
	while (!(x & 0x80000000u)) {
		x <<= 1;
		n++;
	}
	return n;
}

static int bn_bits(const bn *a)
{
	if (a->n == 0)
		return 0;
	return (a->n - 1) * 32 + 32 - bn_clz32(a->w[a->n - 1]);
}

/* big-endian, fixed-length left padded; value must fit in len bytes */
static void bn_to_be(const bn *a, uint8_t *be, size_t len)
{
	size_t i;
	memset(be, 0, len);
	for (i = 0; i < len; i++) {
		size_t rev = len - 1 - i;
		size_t limb = rev / 4;
		unsigned int shift = (unsigned int)((rev % 4) * 8);
		if ((int)limb < a->n)
			be[i] = (uint8_t)(a->w[limb] >> shift);
	}
}

static int bn_from_be(bn *a, const uint8_t *be, size_t len)
{
	size_t i;
	if ((len + 3) / 4 > BN_LIMBS)
		return -1;
	bn_zero(a);
	for (i = 0; i < len; i++) {
		size_t rev = len - 1 - i;
		size_t limb = rev / 4;
		unsigned int shift = (unsigned int)((rev % 4) * 8);
		a->w[limb] |= ((uint32_t)be[i]) << shift;
	}
	a->n = (int)((len + 3) / 4);
	bn_trim(a);
	return 0;
}

static int bn_cmp(const bn *a, const bn *b)
{
	int i;
	if (a->n != b->n)
		return a->n < b->n ? -1 : 1;
	for (i = a->n - 1; i >= 0; i--)
		if (a->w[i] != b->w[i])
			return a->w[i] < b->w[i] ? -1 : 1;
	return 0;
}

/* r = a + b; the result may grow by one limb (up to BN_LIMBS total) */
static int bn_add(bn *r, const bn *a, const bn *b)
{
	const bn *lo = a->n <= b->n ? a : b;
	const bn *hi = a->n <= b->n ? b : a;
	uint32_t out[BN_LIMBS];
	uint64_t carry = 0;
	int n = hi->n;
	int i;

	for (i = 0; i < hi->n; i++) {
		uint64_t s = (uint64_t)hi->w[i] + (i < lo->n ? lo->w[i] : 0) + carry;
		out[i] = (uint32_t)s;
		carry = s >> 32;
	}
	if (carry) {
		if (hi->n >= BN_LIMBS)
			return -1;
		out[hi->n] = (uint32_t)carry;
		n++;
	}
	memset(r, 0, sizeof(*r));
	memcpy(r->w, out, (size_t)n * 4);
	r->n = n;
	bn_trim(r);
	return 0;
}

/* r = a - b; requires a >= b */
static int bn_sub(bn *r, const bn *a, const bn *b)
{
	uint32_t out[BN_LIMBS];
	uint64_t borrow = 0;
	int i;

	if (bn_cmp(a, b) < 0)
		return -1;
	for (i = 0; i < a->n; i++) {
		uint64_t s = (uint64_t)(i < b->n ? b->w[i] : 0) + borrow;
		uint64_t d = (uint64_t)a->w[i];
		out[i] = (uint32_t)(d - s);
		borrow = d >= s ? 0 : 1;
	}
	memset(r, 0, sizeof(*r));
	memcpy(r->w, out, (size_t)a->n * 4);
	r->n = a->n;
	bn_trim(r);
	return 0;
}

/* r = a * b; r must hold a->n + b->n limbs (caller sized buffer) */
static void bn_mul_raw(const bn *a, const bn *b, uint32_t *r)
{
	int i, j;
	int rn = a->n + b->n;

	memset(r, 0, (size_t)rn * 4);
	for (i = 0; i < a->n; i++) {
		uint64_t carry = 0;
		for (j = 0; j < b->n; j++) {
			uint64_t t = (uint64_t)a->w[i] * b->w[j] + r[i + j] + carry;
			r[i + j] = (uint32_t)t;
			carry = t >> 32;
		}
		r[i + b->n] = (uint32_t)carry;
	}
}

static int bn_from_limbs(bn *a, const uint32_t *u, int un)
{
	if (un > BN_LIMBS)
		return -1;
	memset(a, 0, sizeof(*a));
	memcpy(a->w, u, (size_t)un * 4);
	a->n = un;
	bn_trim(a);
	return 0;
}

static int bn_dec(bn *a)
{
	int i;
	if (a->n == 0)
		return -1;
	for (i = 0; i < a->n; i++) {
		if (a->w[i]-- != 0)
			break;
	}
	bn_trim(a);
	return 0;
}

static void bn_shr1(bn *a)
{
	int i;
	for (i = 0; i < a->n; i++) {
		uint32_t next = (i + 1 < a->n) ? a->w[i + 1] : 0;
		a->w[i] = (a->w[i] >> 1) | (next << 31);
	}
	bn_trim(a);
}

static uint32_t bn_mod_u32(const bn *a, uint32_t m)
{
	uint64_t r = 0;
	int i;
	for (i = a->n - 1; i >= 0; i--)
		r = ((r << 32) | a->w[i]) % m;
	return (uint32_t)r;
}

/*
 * Knuth algorithm D (Hacker's Delight divmnu): divide little-endian u[mu]
 * by v[vn], normalized by s = clz(v[vn-1]). q needs mu+2 limbs,
 * r needs vn limbs (shifted back by s).
 */
static int divmod_limbs(uint32_t *q, int *qn, uint32_t *r,
	const uint32_t *u, int mu, const uint32_t *v, int vn)
{
	uint32_t un[BN_LIMBS2 + 2];
	uint32_t vnrm[BN_LIMBS];
	uint32_t carry;
	int s, i, j, ulen;

	if (vn <= 0 || v[vn - 1] == 0)
		return -1;

	if (mu < vn) {
		q[0] = 0;
		*qn = 0;
		memset(r, 0, (size_t)vn * 4);
		memcpy(r, u, (size_t)mu * 4);
		return 0;
	}

	s = bn_clz32(v[vn - 1]);

	/* normalize divisor: top s bits of v[vn-1] are zero, result fits vn */
	carry = 0;
	for (i = 0; i < vn; i++) {
		uint64_t w = ((uint64_t)v[i] << s) | carry;
		vnrm[i] = (uint32_t)w;
		carry = w >> 32;
	}
	if (carry)
		return -1;

	/* normalize dividend into mu+1 limbs, one extra zero digit */
	memset(un, 0, sizeof(un));
	carry = 0;
	for (i = 0; i < mu; i++) {
		uint64_t w = ((uint64_t)u[i] << s) | carry;
		un[i] = (uint32_t)w;
		carry = w >> 32;
	}
	un[mu] = (uint32_t)carry;
	ulen = mu + 1;

	if (vn == 1) {
		uint64_t rem = 0;
		for (j = ulen - 1; j >= 0; j--) {
			uint64_t cur = (rem << 32) | un[j];
			q[j] = (uint32_t)(cur / vnrm[0]);
			rem = cur % vnrm[0];
		}
		*qn = ulen;
		while (*qn > 0 && q[*qn - 1] == 0)
			(*qn)--;
		r[0] = (uint32_t)(rem >> s);
		return 0;
	}

	for (j = ulen - vn; j >= 0; j--) {
		uint64_t num = ((uint64_t)un[j + vn] << 32) | un[j + vn - 1];
		uint64_t qhat = num / vnrm[vn - 1];
		uint64_t rhat = num % vnrm[vn - 1];
		int64_t t;
		int64_t k;

		while (qhat >= (1ULL << 32)
			|| qhat * vnrm[vn - 2] > (rhat << 32) + un[j + vn - 2]) {
			qhat--;
			rhat += vnrm[vn - 1];
			if (rhat >= (1ULL << 32))
				break;
		}

		k = 0;
		for (i = 0; i < vn; i++) {
			uint64_t p = qhat * vnrm[i];
			t = (int64_t)un[i + j] - k - (int64_t)(uint32_t)p;
			un[i + j] = (uint32_t)t;
			k = (int64_t)(p >> 32) - (t >> 32);
		}
		t = (int64_t)un[j + vn] - k;
		un[j + vn] = (uint32_t)t;
		q[j] = (uint32_t)qhat;
		if (t < 0) {
			q[j]--;
			k = 0;
			for (i = 0; i < vn; i++) {
				t = (int64_t)un[i + j] + (int64_t)vnrm[i] + k;
				un[i + j] = (uint32_t)t;
				k = t >> 32;
			}
			un[j + vn] = (uint32_t)((int64_t)un[j + vn] + k);
		}
	}

	*qn = ulen - vn + 1;
	while (*qn > 0 && q[*qn - 1] == 0)
		(*qn)--;

	if (s == 0) {
		memcpy(r, un, (size_t)vn * 4);
	} else {
		for (i = 0; i < vn; i++) {
			uint32_t hi = (i + 1 < vn) ? (un[i + 1] << (32 - s)) : 0;
			r[i] = (un[i] >> s) | hi;
		}
	}
	return 0;
}

/* q = u / v, r = u % v; u given as raw limbs, q buffer internal */
static int bn_divmod(bn *q, bn *r, const uint32_t *u, int mu, const bn *v)
{
	uint32_t qbuf[BN_LIMBS2 + 2];
	uint32_t rbuf[BN_LIMBS];
	int qn = 0;

	if (divmod_limbs(qbuf, &qn, rbuf, u, mu, v->w, v->n) != 0)
		return -1;
	if (qn > BN_LIMBS)
		return -1;
	if (bn_from_limbs(q, qbuf, qn) != 0)
		return -1;
	if (bn_from_limbs(r, rbuf, v->n) != 0)
		return -1;
	return 0;
}

static int bn_mod(bn *r, const bn *a, const bn *m)
{
	bn q;
	return bn_divmod(&q, r, a->w, a->n, m);
}

static int bn_modmul(bn *r, const bn *a, const bn *b, const bn *m)
{
	bn aa, bb, q, rr;
	uint32_t prod[BN_LIMBS2];
	int rn;

	if (bn_mod(&aa, a, m) != 0)
		return -1;
	if (bn_mod(&bb, b, m) != 0)
		return -1;
	if (aa.n == 0 || bb.n == 0) {
		bn_zero(r);
		return 0;
	}
	rn = aa.n + bb.n;
	bn_mul_raw(&aa, &bb, prod);
	if (bn_divmod(&q, &rr, prod, rn, m) != 0)
		return -1;
	*r = rr;
	return 0;
}

/* r = a^e mod m, square-and-multiply, MSB first */
static int bn_modexp(bn *r, const bn *a, const bn *e, const bn *m)
{
	bn base, acc;
	int i, b;

	if (m->n == 0)
		return -1;
	if (bn_mod(&base, a, m) != 0)
		return -1;
	bn_set_u32(&acc, 1);
	for (i = e->n - 1; i >= 0; i--) {
		uint32_t limb = e->w[i];
		for (b = 31; b >= 0; b--) {
			if (bn_modmul(&acc, &acc, &acc, m) != 0)
				return -1;
			if ((limb >> b) & 1) {
				if (bn_modmul(&acc, &acc, &base, m) != 0)
					return -1;
			}
		}
	}
	*r = acc;
	return 0;
}

/*
 * out = a^-1 mod m via extended Euclid. s values are kept reduced mod m:
 * only the congruence r_i == s_i * a (mod m) is needed, so every s stays
 * inside [0, m) and no signed bignum representation is required.
 */
static int bn_modinv(bn *out, const bn *a, const bn *m)
{
	bn r0, r1, q, t, pm, s0, s1, sn;
	uint32_t prod[BN_LIMBS2];

	if (m->n == 0)
		return -1;
	if (bn_divmod(&q, &r1, a->w, a->n, m) != 0)
		return -1;
	r0 = *m;
	bn_zero(&s0);
	bn_set_u32(&s1, 1);

	while (r1.n != 0) {
		int cmp;

		if (bn_divmod(&q, &t, r0.w, r0.n, &r1) != 0)
			return -1;
		r0 = r1;
		r1 = t;

		/* sn = (s0 - q*s1) mod m */
		if (q.n == 0 || s1.n == 0) {
			bn_zero(&pm);
		} else {
			bn mulq;
			if (q.n + s1.n > BN_LIMBS2)
				return -1;
			bn_mul_raw(&q, &s1, prod);
			/* prod can be up to 128 limbs: reduce via raw divmod */
			{
				bn pmb;
				if (bn_divmod(&mulq, &pmb, prod, q.n + s1.n, m) != 0)
					return -1;
				pm = pmb;
			}
		}
		cmp = bn_cmp(&s0, &pm);
		if (cmp == 0) {
			bn_zero(&sn);
		} else if (cmp > 0) {
			if (bn_sub(&sn, &s0, &pm) != 0)
				return -1;
		} else {
			bn mp;
			if (bn_sub(&mp, m, &pm) != 0)
				return -1;
			if (bn_add(&sn, &s0, &mp) != 0)
				return -1;
		}
		s0 = s1;
		s1 = sn;
	}
	if (!(r0.n == 1 && r0.w[0] == 1))
		return -1;
	*out = s0;
	return 0;
}

static const uint32_t mr_bases[] = {
	2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53
};

static int bn_is_prime(const bn *n)
{
	bn d, x, e, nm1;
	int s = 0, i, b;
	uint32_t t;

	if (n->n == 0)
		return 0;
	if (n->n == 1)
		return n->w[0] == 2 || n->w[0] == 3;
	if ((n->w[0] & 1) == 0)
		return 0;

	for (t = 3; t < 1000; t += 2) {
		if (bn_mod_u32(n, t) == 0)
			return 0;
	}

	nm1 = *n;
	if (bn_dec(&nm1) != 0)
		return 0;
	d = nm1;
	while ((d.w[0] & 1) == 0) {
		bn_shr1(&d);
		s++;
	}

	for (b = 0; b < (int)(sizeof(mr_bases) / sizeof(mr_bases[0])); b++) {
		bn_set_u32(&e, mr_bases[b]);
		if (bn_modexp(&x, &e, &d, n) != 0)
			return 0;
		if (x.n == 1 && x.w[0] == 1)
			continue;
		if (bn_cmp(&x, &nm1) == 0)
			continue;
		for (i = 1; i < s; i++) {
			if (bn_modmul(&x, &x, &x, n) != 0)
				return 0;
			if (bn_cmp(&x, &nm1) == 0)
				break;
			if (x.n == 1 && x.w[0] == 1)
				return 0;
		}
		if (i >= s)
			return 0;
	}
	return 1;
}

static int bn_rand_prime(bn *p, int bits)
{
	uint8_t buf[256];
	int bytes = bits / 8;

	if (bits < 512 || bits > 2048 || (bits % 8) != 0)
		return -1;
	for (;;) {
		if (rand_bytes(buf, (size_t)bytes) != 1)
			return -1;
		buf[0] |= 0x80;		/* exactly `bits` long */
		buf[bytes - 1] |= 0x01;	/* odd */
		if (bn_from_be(p, buf, (size_t)bytes) != 0)
			return -1;
		gmssl_secure_clear(buf, sizeof(buf));
		if (bn_is_prime(p))
			return 0;
	}
}

static void rsa_fill_pub(RSArefPublicKey *pub, const bn *n, const bn *e,
	unsigned int keybits)
{
	memset(pub, 0, sizeof(*pub));
	pub->bits = keybits;
	bn_to_be(n, pub->m, RSAref_MAX_LEN);
	bn_to_be(e, pub->e, RSAref_MAX_LEN);
}

int softsdf_rsa_keygen(unsigned int keybits, RSArefPublicKey *pub, RSArefPrivateKey *priv)
{
	bn p, q, n, pm1, qm1, phi, e, d, dp, dq, qi;
	uint32_t prod[BN_LIMBS2];
	int pn;

	if (pub == NULL || priv == NULL)
		return -1;
	if (keybits != 1024 && keybits != 2048)
		return -1;

	for (;;) {
		if (bn_rand_prime(&p, (int)keybits / 2) != 0)
			return -1;
		if (bn_rand_prime(&q, (int)keybits / 2) != 0)
			return -1;
		if (bn_cmp(&p, &q) == 0)
			continue;

		pn = p.n + q.n;
		bn_mul_raw(&p, &q, prod);
		if (bn_from_limbs(&n, prod, pn) != 0)
			return -1;
		if (bn_bits(&n) != (int)keybits)
			continue;	/* N must be exactly keybits long */

		pm1 = p;
		if (bn_dec(&pm1) != 0)
			continue;
		qm1 = q;
		if (bn_dec(&qm1) != 0)
			continue;
		pn = pm1.n + qm1.n;
		bn_mul_raw(&pm1, &qm1, prod);
		if (bn_from_limbs(&phi, prod, pn) != 0)
			return -1;

		bn_set_u32(&e, 65537);
		if (bn_modinv(&d, &e, &phi) != 0)
			continue;	/* gcd(e, phi) != 1: extremely unlikely */
		if (bn_mod(&dp, &d, &pm1) != 0)
			return -1;
		if (bn_mod(&dq, &d, &qm1) != 0)
			return -1;
		if (bn_modinv(&qi, &q, &p) != 0)
			continue;

		memset(priv, 0, sizeof(*priv));
		priv->bits = keybits;
		bn_to_be(&n, priv->m, RSAref_MAX_LEN);
		bn_to_be(&e, priv->e, RSAref_MAX_LEN);
		bn_to_be(&d, priv->d, RSAref_MAX_LEN);
		bn_to_be(&p, priv->prime[0], RSAref_MAX_PLEN);
		bn_to_be(&q, priv->prime[1], RSAref_MAX_PLEN);
		bn_to_be(&dp, priv->pexp[0], RSAref_MAX_PLEN);
		bn_to_be(&dq, priv->pexp[1], RSAref_MAX_PLEN);
		bn_to_be(&qi, priv->coef, RSAref_MAX_PLEN);
		rsa_fill_pub(pub, &n, &e, keybits);

		gmssl_secure_clear(&d, sizeof(d));
		gmssl_secure_clear(&dp, sizeof(dp));
		gmssl_secure_clear(&dq, sizeof(dq));
		gmssl_secure_clear(prod, sizeof(prod));
		return 0;
	}
}

static int bn_all_zero(const uint8_t *buf, size_t len)
{
	size_t i;
	for (i = 0; i < len; i++) {
		if (buf[i] != 0)
			return 0;
	}
	return 1;
}

int softsdf_rsa_check_keypair(const RSArefPublicKey *pub, const RSArefPrivateKey *priv)
{
	bn n, p, q, e, d, dp, dq, qi, pm1, qm1, t;
	uint32_t prod[BN_LIMBS2];
	int pn;

	if (pub == NULL || priv == NULL)
		return -1;
	if (pub->bits != priv->bits)
		return -1;
	if (pub->bits != 1024 && pub->bits != 2048)
		return -1;
	if (memcmp(pub->m, priv->m, RSAref_MAX_LEN) != 0)
		return -1;
	if (memcmp(pub->e, priv->e, RSAref_MAX_LEN) != 0)
		return -1;

	/* fields are fixed-width, right-aligned (left zero padded) */
	if (bn_from_be(&n, pub->m, RSAref_MAX_LEN) != 0)
		return -1;
	if (bn_from_be(&e, priv->e, RSAref_MAX_LEN) != 0)
		return -1;
	if (bn_from_be(&d, priv->d, RSAref_MAX_LEN) != 0)
		return -1;
	if (bn_from_be(&p, priv->prime[0], RSAref_MAX_PLEN) != 0)
		return -1;
	if (bn_from_be(&q, priv->prime[1], RSAref_MAX_PLEN) != 0)
		return -1;
	if (bn_from_be(&dp, priv->pexp[0], RSAref_MAX_PLEN) != 0)
		return -1;
	if (bn_from_be(&dq, priv->pexp[1], RSAref_MAX_PLEN) != 0)
		return -1;
	if (bn_from_be(&qi, priv->coef, RSAref_MAX_PLEN) != 0)
		return -1;

	/* N == p*q */
	pn = p.n + q.n;
	bn_mul_raw(&p, &q, prod);
	{
		bn pq;
		if (bn_from_limbs(&pq, prod, pn) != 0)
			return -1;
		if (bn_cmp(&pq, &n) != 0)
			return -1;
	}

	pm1 = p;
	qm1 = q;
	if (bn_dec(&pm1) != 0 || bn_dec(&qm1) != 0)
		return -1;

	/* e*d == 1 (mod p-1) and (mod q-1); reduce via modmul so the
	 * e*d product never leaves the fixed limb budget */
	{
		bn m1, m2;
		if (bn_modmul(&m1, &e, &d, &pm1) != 0)
			return -1;
		if (bn_modmul(&m2, &e, &d, &qm1) != 0)
			return -1;
		bn_set_u32(&t, 1);
		if (bn_cmp(&m1, &t) != 0 || bn_cmp(&m2, &t) != 0)
			return -1;
	}

	/* dp == d mod (p-1), dq == d mod (q-1) */
	{
		bn m1, m2;
		if (bn_mod(&m1, &d, &pm1) != 0)
			return -1;
		if (bn_mod(&m2, &d, &qm1) != 0)
			return -1;
		if (bn_cmp(&m1, &dp) != 0 || bn_cmp(&m2, &dq) != 0)
			return -1;
	}

	/* q*qi == 1 (mod p) */
	pn = q.n + qi.n;
	bn_mul_raw(&q, &qi, prod);
	{
		bn m1;
		if (bn_from_limbs(&t, prod, pn) != 0)
			return -1;
		if (bn_mod(&m1, &t, &p) != 0)
			return -1;
		bn_set_u32(&t, 1);
		if (bn_cmp(&m1, &t) != 0)
			return -1;
	}
	return 0;
}

int softsdf_rsa_public_op(const RSArefPublicKey *pub,
	const uint8_t *in, size_t inlen, uint8_t *out)
{
	bn base, mod, ex, r;
	size_t k;

	if (pub == NULL || in == NULL || out == NULL)
		return -1;
	if (pub->bits != 1024 && pub->bits != 2048)
		return -1;
	k = pub->bits / 8;
	if (inlen > k)
		return -1;
	if (bn_from_be(&base, in, inlen) != 0)
		return -1;
	if (bn_from_be(&mod, pub->m, RSAref_MAX_LEN) != 0)
		return -1;
	if (bn_from_be(&ex, pub->e, RSAref_MAX_LEN) != 0)
		return -1;
	if (base.n != 0 && bn_cmp(&base, &mod) >= 0)
		return -1;
	if (bn_modexp(&r, &base, &ex, &mod) != 0)
		return -1;
	bn_to_be(&r, out, k);
	return 0;
}

int softsdf_rsa_private_op(const RSArefPrivateKey *priv,
	const uint8_t *in, size_t inlen, uint8_t *out)
{
	bn base, mod, d, p, q, dp, dq, qi, t1, t2, tm, diff, h, prod2, res;
	uint32_t prod[BN_LIMBS2];
	size_t k;
	int pn, have_crt;

	if (priv == NULL || in == NULL || out == NULL)
		return -1;
	if (priv->bits != 1024 && priv->bits != 2048)
		return -1;
	k = priv->bits / 8;
	if (inlen > k)
		return -1;
	if (bn_from_be(&base, in, inlen) != 0)
		return -1;
	/* fields are fixed-width, right-aligned (left zero padded) */
	if (bn_from_be(&mod, priv->m, RSAref_MAX_LEN) != 0)
		return -1;
	if (base.n != 0 && bn_cmp(&base, &mod) >= 0)
		return -1;

	have_crt = !bn_all_zero(priv->prime[0], RSAref_MAX_PLEN)
		&& !bn_all_zero(priv->prime[1], RSAref_MAX_PLEN)
		&& !bn_all_zero(priv->pexp[0], RSAref_MAX_PLEN)
		&& !bn_all_zero(priv->pexp[1], RSAref_MAX_PLEN)
		&& !bn_all_zero(priv->coef, RSAref_MAX_PLEN);

	if (have_crt) {
		/* Garner: res = t2 + q * (((t1 - t2) mod p) * qi mod p) */
		if (bn_from_be(&p, priv->prime[0], RSAref_MAX_PLEN) != 0)
			return -1;
		if (bn_from_be(&q, priv->prime[1], RSAref_MAX_PLEN) != 0)
			return -1;
		if (bn_from_be(&dp, priv->pexp[0], RSAref_MAX_PLEN) != 0)
			return -1;
		if (bn_from_be(&dq, priv->pexp[1], RSAref_MAX_PLEN) != 0)
			return -1;
		if (bn_from_be(&qi, priv->coef, RSAref_MAX_PLEN) != 0)
			return -1;

		if (bn_modexp(&t1, &base, &dp, &p) != 0)
			return -1;
		if (bn_modexp(&t2, &base, &dq, &q) != 0)
			return -1;
		if (bn_mod(&tm, &t2, &p) != 0)
			return -1;
		if (bn_cmp(&t1, &tm) >= 0) {
			if (bn_sub(&diff, &t1, &tm) != 0)
				return -1;
		} else {
			bn mp;
			if (bn_sub(&mp, &p, &tm) != 0)
				return -1;
			if (bn_add(&diff, &t1, &mp) != 0)
				return -1;
		}
		if (bn_modmul(&h, &diff, &qi, &p) != 0)
			return -1;
		/* res = t2 + q*h, with q*h < N and res < N */
		pn = q.n + h.n;
		bn_mul_raw(&q, &h, prod);
		if (bn_from_limbs(&prod2, prod, pn) != 0)
			return -1;
		if (bn_add(&res, &t2, &prod2) != 0)
			return -1;
	} else {
		if (bn_from_be(&d, priv->d, RSAref_MAX_LEN) != 0)
			return -1;
		if (bn_modexp(&res, &base, &d, &mod) != 0)
			return -1;
	}

	if (bn_cmp(&res, &mod) >= 0)
		return -1;
	bn_to_be(&res, out, k);
	gmssl_secure_clear(&res, sizeof(res));
	return 0;
}

int softsdf_rsa_pkcs1_encrypt(const RSArefPublicKey *pub,
	const uint8_t *in, size_t inlen, uint8_t *out)
{
	uint8_t em[256];
	bn mod, ex, embn, r;
	size_t k, pslen, i;

	if (pub == NULL || in == NULL || out == NULL)
		return -1;
	if (pub->bits != 1024 && pub->bits != 2048)
		return -1;
	k = pub->bits / 8;
	if (k < 11 || inlen > k - 11)
		return -1;
	if (inlen > 255)
		return -1;

	/* EME-PKCS1-v1_5 type 2: 0x00 || 0x02 || PS || 0x00 || M */
	em[0] = 0x00;
	em[1] = 0x02;
	pslen = k - 3 - inlen;
	if (rand_bytes(em + 2, pslen) != 1)
		return -1;
	for (i = 0; i < pslen; i++) {
		while (em[2 + i] == 0x00) {
			if (rand_bytes(&em[2 + i], 1) != 1)
				return -1;
		}
	}
	em[2 + pslen] = 0x00;
	memcpy(em + 3 + pslen, in, inlen);

	if (bn_from_be(&mod, pub->m, RSAref_MAX_LEN) != 0)
		goto fail;
	if (bn_from_be(&ex, pub->e, RSAref_MAX_LEN) != 0)
		goto fail;
	if (bn_from_be(&embn, em, k) != 0)
		goto fail;
	if (bn_cmp(&embn, &mod) >= 0)	/* EM < N */
		goto fail;
	if (bn_modexp(&r, &embn, &ex, &mod) != 0)
		goto fail;
	bn_to_be(&r, out, k);
	gmssl_secure_clear(em, sizeof(em));
	return 0;

fail:
	gmssl_secure_clear(em, sizeof(em));
	return -1;
}

int softsdf_rsa_pkcs1_unpad(const uint8_t *em, size_t emlen,
	uint8_t *out, size_t outcap, size_t *outlen)
{
	size_t i, n;

	if (em == NULL || out == NULL || outlen == NULL)
		return -1;
	if (emlen < 11 || em[0] != 0x00 || em[1] != 0x02)
		return -1;
	for (i = 2; i < emlen; i++) {
		if (em[i] == 0x00) {
			if (i < 10)	/* PS must be at least 8 bytes */
				return -1;
			n = emlen - i - 1;
			if (n > outcap)
				return -1;
			*outlen = n;
			memcpy(out, em + i + 1, n);
			return 0;
		}
	}
	return -1;
}

int softsdf_rsa_pkcs1_decrypt(const RSArefPrivateKey *priv,
	const uint8_t *in, size_t inlen, uint8_t *out, size_t outcap,
	size_t *outlen)
{
	uint8_t em[256];
	size_t k;

	if (priv == NULL || in == NULL || out == NULL || outlen == NULL)
		return -1;
	if (priv->bits != 1024 && priv->bits != 2048)
		return -1;
	k = priv->bits / 8;
	if (inlen != k)
		return -1;
	if (softsdf_rsa_private_op(priv, in, inlen, em) != 0)
		return -1;
	return softsdf_rsa_pkcs1_unpad(em, k, out, outcap, outlen);
}

void softsdf_rsa_pub_from_priv(const RSArefPrivateKey *priv, RSArefPublicKey *pub)
{
	memset(pub, 0, sizeof(*pub));
	pub->bits = priv->bits;
	memcpy(pub->m, priv->m, sizeof(pub->m));
	memcpy(pub->e, priv->e, sizeof(pub->e));
}

/* 私有密钥文件以 0600 创建(POSIX)/以读写属性创建(Windows),
 * 避免 fopen 默认 0644 在写入前留下可读窗口。 */
static FILE *rsa_open_private_file(const char *path)
{
	int fd;
	FILE *file;

#ifdef _WIN32
	fd = _open(path, _O_WRONLY | _O_CREAT | _O_TRUNC | _O_BINARY,
		_S_IREAD | _S_IWRITE);
	file = fd >= 0 ? _fdopen(fd, "wb") : NULL;
	if (fd >= 0 && file == NULL)
		_close(fd);
#else
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	file = fd >= 0 ? fdopen(fd, "wb") : NULL;
	if (fd >= 0 && file == NULL)
		close(fd);
#endif
	return file;
}

int softsdf_rsa_keyfile_save(const char *path, const RSArefPrivateKey *priv)
{
	FILE *file;

	if (path == NULL || priv == NULL)
		return -1;
	if ((file = rsa_open_private_file(path)) == NULL)
		return -1;
	if (fwrite(priv, 1, sizeof(*priv), file) != sizeof(*priv)) {
		fclose(file);
		return -1;
	}
	fclose(file);
	return 0;
}

int softsdf_rsa_keyfile_load(const char *path, RSArefPrivateKey *priv)
{
	FILE *file;

	if (path == NULL || priv == NULL)
		return -1;
	if ((file = fopen(path, "rb")) == NULL)
		return -1;
	if (fread(priv, 1, sizeof(*priv), file) != sizeof(*priv)) {
		fclose(file);
		return -1;
	}
	fclose(file);
	return 0;
}
