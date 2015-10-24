/*
 * ycache.c
 *
 * Copyright (C) 2015  Eric Zhang <gd.yi@139.com>
 * Copyright (C) 2015
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/cpu.h>
#include <linux/spinlock.h>
#include <linux/highmem.h>
#include <linux/llist.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/string.h>
#include <linux/rbtree.h>
#include <linux/crypto.h>
#include <crypto/md5.h>
#include <linux/scatterlist.h>
#include <linux/err.h>
#include <linux/idr.h>
#include "tmem.h"

#ifdef CONFIG_CLEANCACHE
#include <linux/cleancache.h>
#endif
#ifdef CONFIG_FRONTSWAP
#include <linux/frontswap.h>
#endif

/*#define YCACHE_GFP_MASK \
	(__GFP_FS | __GFP_NORETRY | __GFP_NOWARN | __GFP_NOMEMALLOC)*/
#define YCACHE_GFP_MASK GFP_KERNEL

#define LOCAL_CLIENT ((uint16_t)-1)

/*********************************
* statistics
**********************************/
/* Total pages used for storage */
static atomic_t ycache_total_pages = ATOMIC_INIT(0);
/* The number of pages deduplicated */
static atomic_t ycache_duplicate_pages = ATOMIC_INIT(0);

/*
 * The statistics below are not protected from concurrent access for
 * performance reasons so they may not be a 100% accurate.  However,
 * they do provide useful information on roughly how many times a
 * certain event is occurring.
*/

/* Store failed because the ycache_entry  could not be allocated (rare) */
static u64 ycache_yentry_kmemcache_fail;
/* Store failed because the page_entry metadata could not be allocated (rare) */
static u64 ycache_pentry_kmemcache_fail;
/* Get md5 from page failed */
static u64 ycache_md5_fail;
/* counters for debugging */
static u64 ycache_failed_get_free_pages;
static u64 ycache_failed_alloc;
static u64 ycache_put_to_flush;
/* useful stats not collected by cleancache or frontswap */
static u64 ycache_flush_total;
static u64 ycache_flush_found;
static u64 ycache_flobj_total;
static u64 ycache_flobj_found;
static u64 ycache_failed_eph_puts;
static u64 ycache_failed_pers_puts;
/* tmem statistics */
static atomic_t ycache_curr_eph_pampd_count = ATOMIC_INIT(0);
static unsigned long ycache_curr_eph_pampd_count_max;
static atomic_t ycache_curr_pers_pampd_count = ATOMIC_INIT(0);
static unsigned long ycache_curr_pers_pampd_count_max;

/*********************************
* data structures
**********************************/
/*
 * struct page_tree
 *
 * rbroot - red-black tree root
 */
struct page_tree {
	struct rb_root rbroot;
};

struct page_tree *page_tree = NULL;
/*
 * struct page_entry
 *
 * page - pointer to a page, this is where data is actually stored
 * entry - pointer to a ycache_entry in order to find corresponding
 * 		    ycache_entry
 * rbnode - red-black tree node
 * hash - contains the hash value. Since we use array to store it, we
 * 			need to hardcode the size.
 */
struct page_entry {
	struct page *page;
	struct ycache_entry *entry;
	struct rb_node rbnode;
	u8 hash[MD5_DIGEST_SIZE];
};

/*********************************
* page entry functions
**********************************/
static struct kmem_cache *page_entry_cache;

static int __init page_entry_cache_create(void)
{
	pr_debug("call %s()\n", __FUNCTION__);
	page_entry_cache = KMEM_CACHE(page_entry, 0);
	return page_entry_cache == NULL;
}

static void __init page_entry_cache_destroy(void)
{
	pr_debug("call %s()\n", __FUNCTION__);
	kmem_cache_destroy(page_entry_cache);
}

/* forward referece */
static void page_entry_cache_free(struct page_entry *);

static struct page_entry *page_entry_cache_alloc(gfp_t gfp)
{
	struct page_entry *entry;

	pr_debug("call %s()\n", __FUNCTION__);
	entry = kmem_cache_alloc(page_entry_cache, gfp);
	if (entry != NULL) {
		/* alloc page*/
		entry->page = alloc_page(gfp | __GFP_HIGHMEM | __GFP_FS);
		if (entry->page != NULL) {
			RB_CLEAR_NODE(&entry->rbnode);
			return entry;
		} else {
			page_entry_cache_free(entry);
			ycache_failed_get_free_pages++;
			return NULL;
		}
	} else {
		ycache_pentry_kmemcache_fail++;
		return NULL;
	}
}

static void page_entry_cache_free(struct page_entry *entry)
{
	pr_debug("call %s()\n", __FUNCTION__);
	if (entry && entry->page != NULL) {
		__free_page(entry->page);
	}
	kmem_cache_free(page_entry_cache, entry);
}

/*********************************
* page entry rbtree functions
**********************************/
static struct page_entry *page_rb_search(struct rb_root *root, u8 *hash)
{
	struct rb_node *node = root->rb_node;
	struct page_entry *entry;
	int i;

	pr_debug("call %s()\n", __FUNCTION__);
	while (node) {
		entry = rb_entry(node, struct page_entry, rbnode);
		i = 0;
		while (i < MD5_DIGEST_SIZE) {
			if (entry->hash[i] > hash[i]) {
				node = node->rb_left;
				break;
			} else if (entry->hash[i] < hash[i]) {
				node = node->rb_right;
				break;
			} else
				i++;
		}

		if (i == MD5_DIGEST_SIZE)
			return entry;
	}
	return NULL;
}

/*
 * In the case that a entry with the same values is found, a pointer to
 * the existing entry is stored in dupentry and the function returns
 * -EEXIST
 */
static int page_rb_insert(struct rb_root *root, struct page_entry *entry,
			  struct page_entry **dupentry)
{
	struct rb_node **link = &root->rb_node, *parent = NULL;
	struct page_entry *tmp_entry;
	int i;

	pr_debug("call %s()\n", __FUNCTION__);
	while (*link) {
		parent = *link;
		tmp_entry = rb_entry(parent, struct page_entry, rbnode);
		i = 0;
		while (i < MD5_DIGEST_SIZE) {
			if (tmp_entry->hash[i] > entry->hash[i]) {
				link = &(*link)->rb_left;
				break;
			} else if (tmp_entry->hash[i] < entry->hash[i]) {
				link = &(*link)->rb_right;
				break;
			} else
				i++;
		}

		if (i == MD5_DIGEST_SIZE) {
			*dupentry = tmp_entry;
			return -EEXIST;
		}
	}
	rb_link_node(&entry->rbnode, parent, link);
	rb_insert_color(&entry->rbnode, root);
	return 0;
}

static void page_rb_erase(struct rb_root *root, struct page_entry *entry)
{
	pr_debug("call %s()\n", __FUNCTION__);
	if (!RB_EMPTY_NODE(&entry->rbnode)) {
		rb_erase(&entry->rbnode, root);
		RB_CLEAR_NODE(&entry->rbnode);
	}
}

static void page_free_entry(struct page_entry *entry)
{
	pr_debug("call %s()\n", __FUNCTION__);
	page_entry_cache_free(entry);
	atomic_dec(&ycache_total_pages);
}

/*
 * plaintext_to_md5 - caculate md5 message digest for a message
 *
 * @src:    The start virtual address of the message
 * @result: Somewhere used to store the md5 value, need 128 bit.
 *          (see include/crypto/md5.h - MD5_DIGEST_SIZE)
 *
 * The user of this function should manage the memory lifecycle of
 *result
 * by himself/herself. The length of the plaintext should not be
 * longer than PAGE_SIZE.
 *
 * Return:  0 if the caculation is successful, <0 if an error was
 *occurred
 *
 */
static int plaintext_to_md5(const void *src, u8 *result)
{
	struct hash_desc desc;
	struct scatterlist sg;
	int ret = 0;

	pr_debug("call %s()\n", __FUNCTION__);
	sg_init_one(&sg, (u8 *)src, PAGE_SIZE);

	desc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	/* fail to allocate a cipher handle */
	if (IS_ERR(desc.tfm)) {
		ret = -EINVAL;
		goto out;
	}
	desc.flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	ret = crypto_hash_init(&desc);
	if (ret)
		goto out;

	ret = crypto_hash_update(&desc, &sg, PAGE_SIZE);
	if (ret)
		goto out;

	ret = crypto_hash_final(&desc, result);
	if (ret)
		goto out;

out:
	crypto_free_hash(desc.tfm);
	if (ret != 0)
		ycache_md5_fail++;
	return ret;
}

static int is_page_same(struct page *p1, struct page *p2)
{
	u8 *src, *dst;
	int i = 0;
	int ret = 0;

	pr_debug("call %s()\n", __FUNCTION__);
	src = kmap_atomic(p1);
	dst = kmap_atomic(p2);
	for (; i < PAGE_SIZE; i++)
		if (src[i] != dst[i])
			goto out;

	ret = 1;
out:
	kunmap_atomic(dst);
	kunmap_atomic(src);
	return ret;
}

/*
 * struct ycache_entry
 * src - pointer to the corresponding page_entry, where
 * list -
 * 		node - when being deduplicated, the ycache_entry is added
 * to
 * 		 	   an deduplicated-page list for future
 * reference
 * 		head - when being unique, the ycache_entry contains the
 *   		   deduplicated-page list head, where deduplicated page
 * could
 *   		   be added to
 */
struct ycache_entry {
	struct page_entry *src;
	union {
		struct llist_head head;
		struct llist_node node;
	} list;
	bool unique;
};

/*********************************
* ycache entry functions
**********************************/
static struct kmem_cache *ycache_entry_cache;

static int __init ycache_entry_cache_create(void)
{
	pr_debug("call %s()\n", __FUNCTION__);
	ycache_entry_cache = KMEM_CACHE(ycache_entry, 0);
	return ycache_entry_cache == NULL;
}

static void __init ycache_entry_cache_destroy(void)
{
	pr_debug("call %s()\n", __FUNCTION__);
	kmem_cache_destroy(ycache_entry_cache);
}

static struct ycache_entry *ycache_entry_cache_alloc(gfp_t gfp)
{
	struct ycache_entry *entry;

	pr_debug("call %s()\n", __FUNCTION__);
	entry = kmem_cache_alloc(ycache_entry_cache, gfp);
	if (!entry) {
		ycache_yentry_kmemcache_fail++;
		return NULL;
	}
	init_llist_head(&entry->list.head);
	return entry;
}

static void ycache_entry_cache_free(struct ycache_entry *entry)
{
	pr_debug("call %s()\n", __FUNCTION__);
	kmem_cache_free(ycache_entry_cache, entry);
}

/* TODO: a big lock may hurt performance? */
/* when editing either ycache_entry or page_tree, lock must be held */
struct ycache_client {
	struct idr tmem_pools;
	atomic_t refcount;
	spinlock_t lock;
	bool allocated;
};

static struct ycache_client ycache_host;

static int init_ycache_host(void)
{
	pr_debug("call %s()\n", __FUNCTION__);
	if (ycache_host.allocated)
		return 0;
	else {
		ycache_host.allocated = 1;
		atomic_set(&ycache_host.refcount, 0);
		idr_init(&ycache_host.tmem_pools);
		spin_lock_init(&ycache_host.lock);

		if (page_tree == NULL) {
			page_tree =
			    kmalloc(sizeof(struct page_tree), GFP_KERNEL);
			if (!page_tree) {
				pr_err("page_tree allocatinon failed\n");
				return -ENOMEM;
			}

			page_tree->rbroot = RB_ROOT;
		}
	}
	return 0;
}

/*
 * Tmem operations assume the pool_id implies the invoking client.
 * ycache only has one client (the kernel itself): LOCAL_CLIENT.
 */
static struct tmem_pool *ycache_get_pool_by_id(uint16_t pool_id)
{
	struct tmem_pool *pool = NULL;

	//	pr_debug("call %s()\n", __FUNCTION__);
	atomic_inc(&ycache_host.refcount);
	pool = idr_find(&ycache_host.tmem_pools, pool_id);
	if (pool)
		atomic_inc(&pool->refcount);
	return pool;
}

static void ycache_put_pool(struct tmem_pool *pool)
{
	//	pr_debug("call %s()\n", __FUNCTION__);
	if (pool == NULL)
		BUG();
	atomic_dec(&pool->refcount);
	atomic_dec(&ycache_host.refcount);
}

/*
 * for now, used named slabs so can easily track usage; later can
 * either just use kmalloc, or perhaps add a slab-like allocator
 * to more carefully manage total memory utilization
 */
static struct kmem_cache *ycache_objnode_cache;
static struct kmem_cache *ycache_obj_cache;
static atomic_t ycache_curr_obj_count = ATOMIC_INIT(0);
static u64 ycache_curr_obj_count_max;
static atomic_t ycache_curr_objnode_count = ATOMIC_INIT(0);
static u64 ycache_curr_objnode_count_max;

static int __init ycache_objnode_cache_create(void)
{
	pr_debug("call %s()\n", __FUNCTION__);
	ycache_objnode_cache = kmem_cache_create(
	    "ycache_objnode", sizeof(struct tmem_objnode), 0, 0, NULL);
	return ycache_objnode_cache == NULL;
}

static void __init ycache_objnode_cache_destroy(void)
{
	pr_debug("call %s()\n", __FUNCTION__);
	kmem_cache_destroy(ycache_objnode_cache);
}

static int __init ycache_obj_cache_create(void)
{
	pr_debug("call %s()\n", __FUNCTION__);
	ycache_obj_cache = kmem_cache_create(
	    "ycache_obj", sizeof(struct tmem_obj), 0, 0, NULL);
	return ycache_obj_cache == NULL;
}

static void __init ycache_obj_cache_destroy(void)
{
	pr_debug("call %s()\n", __FUNCTION__);
	kmem_cache_destroy(ycache_obj_cache);
}

/*
 * to avoid memory allocation recursion (e.g. due to direct reclaim), we
 * preload all necessary data structures so the hostops callbacks never
 * actually do a malloc
 */
struct ycache_preload {
	struct tmem_obj *obj;
	int nr;
	struct tmem_objnode *objnodes[OBJNODE_TREE_MAX_PATH];
};

static DEFINE_PER_CPU(struct ycache_preload, ycache_preloads) = {
    0,
};

static int ycache_do_preload(struct tmem_pool *pool, struct page *page)
{
	struct ycache_preload *kp;
	struct tmem_obj *obj;
	struct tmem_objnode *objnode;
	int ret = -ENOMEM;

	pr_debug("call %s()\n", __FUNCTION__);
	if (unlikely(ycache_objnode_cache == NULL))
		goto out;
	if (unlikely(ycache_obj_cache == NULL))
		goto out;

	/* IRQ has already been disabled. */
	kp = this_cpu_ptr(&ycache_preloads);

	if (!kp->obj) {
		obj = kmem_cache_alloc(ycache_obj_cache, YCACHE_GFP_MASK);
		if (unlikely(obj == NULL)) {
			ycache_failed_alloc++;
			goto out;
		}
		kp->obj = obj;
	}

	while (kp->nr < ARRAY_SIZE(kp->objnodes)) {
		objnode =
		    kmem_cache_alloc(ycache_objnode_cache, YCACHE_GFP_MASK);
		if (unlikely(objnode == NULL)) {
			ycache_failed_alloc++;
			goto out;
		}
		kp->objnodes[kp->nr++] = objnode;
	}

	ret = 0;
out:
	return ret;
}

/*
 * ycache implementation for tmem host ops
 */

static struct tmem_objnode *ycache_objnode_alloc(struct tmem_pool *pool)
{
	struct tmem_objnode *objnode = NULL;
	unsigned long count;
	struct ycache_preload *kp;

	pr_debug("call %s()\n", __FUNCTION__);
	kp = this_cpu_ptr(&ycache_preloads);
	if (kp->nr <= 0)
		goto out;
	objnode = kp->objnodes[kp->nr - 1];
	BUG_ON(objnode == NULL);
	kp->objnodes[kp->nr - 1] = NULL;
	kp->nr--;
	count = atomic_inc_return(&ycache_curr_objnode_count);
	if (count > ycache_curr_objnode_count_max)
		ycache_curr_objnode_count_max = count;
out:
	return objnode;
}

static void ycache_objnode_free(struct tmem_objnode *objnode,
				struct tmem_pool *pool)
{
	pr_debug("call %s()\n", __FUNCTION__);
	atomic_dec(&ycache_curr_objnode_count);
	BUG_ON(atomic_read(&ycache_curr_objnode_count) < 0);
	kmem_cache_free(ycache_objnode_cache, objnode);
}

static struct tmem_obj *ycache_obj_alloc(struct tmem_pool *pool)
{
	struct tmem_obj *obj = NULL;
	unsigned long count;
	struct ycache_preload *kp;

	pr_debug("call %s()\n", __FUNCTION__);
	kp = this_cpu_ptr(&ycache_preloads);
	obj = kp->obj;
	BUG_ON(obj == NULL);
	kp->obj = NULL;
	count = atomic_inc_return(&ycache_curr_obj_count);
	if (count > ycache_curr_obj_count_max)
		ycache_curr_obj_count_max = count;
	return obj;
}

static void ycache_obj_free(struct tmem_obj *obj, struct tmem_pool *pool)
{
	pr_debug("call %s()\n", __FUNCTION__);
	atomic_dec(&ycache_curr_obj_count);
	BUG_ON(atomic_read(&ycache_curr_obj_count) < 0);
	kmem_cache_free(ycache_obj_cache, obj);
}

static struct tmem_hostops ycache_hostops = {
    .obj_alloc = ycache_obj_alloc,
    .obj_free = ycache_obj_free,
    .objnode_alloc = ycache_objnode_alloc,
    .objnode_free = ycache_objnode_free,
};

/*
 * use tmem to manage ycache_entry
 */

static void *ycache_pampd_create(char *data, size_t size, bool raw, int eph,
				 struct tmem_pool *pool, struct tmem_oid *oid,
				 uint32_t index)
{
	void *pampd = NULL;
	struct page *page;
	struct ycache_entry *ycache_entry = NULL;
	struct ycache_entry *head_ycache_entry = NULL;
	struct page_entry *page_entry;
	struct page_entry *dupentry = NULL;
	int result;
	unsigned long count;
	u8 hash[MD5_DIGEST_SIZE];
	u8 *src, *dst;

	pr_debug("call %s()\n", __FUNCTION__);

	page = (struct page *)data;
	src = kmap(page);
	plaintext_to_md5(src, hash);
	kunmap(page);

	ycache_entry = ycache_entry_cache_alloc(YCACHE_GFP_MASK);
	if (ycache_entry == NULL) {
		BUG_ON(ycache_entry == NULL);
		return NULL;
	}

	spin_lock(&ycache_host.lock);
	page_entry = page_rb_search(&page_tree->rbroot, hash);
	/* hash not exists */
	if (page_entry == NULL) {
		spin_unlock(&ycache_host.lock);

		page_entry = page_entry_cache_alloc(YCACHE_GFP_MASK);
		BUG_ON(page_entry == NULL);

		src = kmap(page);
		dst = kmap(page_entry->page);
		memcpy(dst, src, PAGE_SIZE);
		kunmap(page_entry->page);
		kunmap(page);

		/* set page_entry->entry */
		page_entry->entry = ycache_entry;
		/* copy hash values */
		memcpy(page_entry->hash, hash, MD5_DIGEST_SIZE);

		spin_lock(&ycache_host.lock);
		result =
		    page_rb_insert(&page_tree->rbroot, page_entry, &dupentry);
		// this rarely happens, it has to be taken cared of
		// should it happen
		if (result == -EEXIST) {
			page_entry_cache_free(page_entry);
			ycache_entry_cache_free(ycache_entry);
		} else {
			/* set ycache_entry->entry */
			ycache_entry->src = page_entry;
			/* set unique */
			ycache_entry->unique = 1;
			pampd = (void *)ycache_entry;
			atomic_inc(&ycache_total_pages);
		}
		spin_unlock(&ycache_host.lock);
	}
	/* hash exists, compare bit by bit */
	else if (is_page_same(page_entry->page, (struct page *)data)) {
		/* set ycache_entry->entry */
		ycache_entry->src = page_entry;
		/* set deduplicated */
		ycache_entry->unique = 0;
		head_ycache_entry = page_entry->entry;
		/* add new ycache_entry to deduplicated-entry list */
		llist_add(&ycache_entry->list.node,
			  &head_ycache_entry->list.head);

		spin_unlock(&ycache_host.lock);
		pampd = (void *)ycache_entry;
		atomic_inc(&ycache_duplicate_pages);
	}
	/* hash is the same but data is not */
	else {
		/* TODO: add collision handling with frontswap enabled
		 */
		spin_unlock(&ycache_host.lock);
	}

	if (pampd != NULL) {
		if (eph) {
			count = atomic_inc_return(&ycache_curr_eph_pampd_count);
			if (count > ycache_curr_eph_pampd_count_max)
				ycache_curr_eph_pampd_count_max = count;
		} else {
			count =
			    atomic_inc_return(&ycache_curr_pers_pampd_count);
			if (count > ycache_curr_pers_pampd_count_max)
				ycache_curr_pers_pampd_count_max = count;
		}
	}

	return pampd;
}

static int ycache_pampd_get_data(char *data, size_t *bufsize, bool raw,
				 void *pampd, struct tmem_pool *pool,
				 struct tmem_oid *oid, uint32_t index)
{
	struct ycache_entry *entry = NULL;
	u8 *src = NULL;
	int ret = -EINVAL;

	pr_debug("call %s()\n", __FUNCTION__);
	BUG_ON(is_ephemeral(pool));
	BUG_ON(pampd == NULL);
	spin_lock(&ycache_host.lock);
	entry = (struct ycache_entry *)pampd;
	if (entry) {
		BUG_ON(entry->src == NULL);
		BUG_ON(entry->src->page == NULL);
		src = kmap_atomic(entry->src->page);
		memcpy(data, src, PAGE_SIZE);
		kunmap_atomic(src);
	} else {
		goto out;
	}

	ret = 0;
out:
	spin_unlock(&ycache_host.lock);
	return ret;
}

static int ycache_pampd_get_data_and_free(char *data, size_t *bufsize, bool raw,
					  void *pampd, struct tmem_pool *pool,
					  struct tmem_oid *oid, uint32_t index)
{
	struct ycache_entry *entry = NULL;
	struct ycache_entry *head_ycache_entry = NULL;
	struct llist_node *next = NULL;
	u8 *src = NULL;
	int ret = -EINVAL;

	pr_debug("call %s()\n", __FUNCTION__);
	BUG_ON(!is_ephemeral(pool));
	BUG_ON(pampd == NULL);

	spin_lock(&ycache_host.lock);
	entry = (struct ycache_entry *)pampd;
	if (entry) {
		BUG_ON(entry->src == NULL);
		BUG_ON(entry->src->page == NULL);
		src = kmap_atomic(entry->src->page);
		memcpy(data, src, PAGE_SIZE);
		kunmap_atomic(src);
	} else {
		goto out;
	}

	if (entry->unique) {
		if (llist_empty(&entry->list.head)) {
			page_rb_erase(&page_tree->rbroot, entry->src);
			page_free_entry(entry->src);
		} else {
			/* it's soon to be head ycache_entry actually */
			head_ycache_entry =
			    llist_entry(entry->list.head.first,
					struct ycache_entry, list.node);
			next = head_ycache_entry->list.node.next;
			init_llist_head(&head_ycache_entry->list.head);
			if (next != NULL)
				llist_add(next, &head_ycache_entry->list.head);
			entry->src->entry = head_ycache_entry;
		}
	} else {
		head_ycache_entry = entry->src->entry;
		next = head_ycache_entry->list.head.first;
		/* is the first node in the list */
		if (llist_entry(next, struct ycache_entry, list.node) ==
		    entry) {
			head_ycache_entry->list.head.first = next->next;
		}
		/* not the first node in the list  */
		else {
			while (next &&
			       llist_entry(next->next, struct ycache_entry,
					   list.node) != entry)
				next = next->next;
			next->next = next->next->next;
		}
	}
	ycache_entry_cache_free(entry);

	if (is_ephemeral(pool)) {
		atomic_dec(&ycache_curr_eph_pampd_count);
		BUG_ON(atomic_read(&ycache_curr_eph_pampd_count) < 0);
	} else {
		atomic_dec(&ycache_curr_pers_pampd_count);
		BUG_ON(atomic_read(&ycache_curr_pers_pampd_count) < 0);
	}

	ret = 0;
out:
	spin_unlock(&ycache_host.lock);
	return ret;
}

/*
 * free the pampd and remove it from any ycache lists
 * pampd must no longer be pointed to from any tmem data structures!
 */
static void ycache_pampd_free(void *pampd, struct tmem_pool *pool,
			      struct tmem_oid *oid, uint32_t index)
{
	struct ycache_entry *ycache_entry;
	struct ycache_entry *head_ycache_entry;
	struct llist_node *next;

	pr_debug("call %s()\n", __FUNCTION__);

	spin_lock(&ycache_host.lock);
	ycache_entry = (struct ycache_entry *)pampd;
	if (ycache_entry->unique) {
		if (llist_empty(&ycache_entry->list.head)) {
			page_rb_erase(&page_tree->rbroot, ycache_entry->src);
			page_free_entry(ycache_entry->src);
		} else {
			/* it's soon to be head ycache_entry actually */
			head_ycache_entry =
			    llist_entry(ycache_entry->list.head.first,
					struct ycache_entry, list.node);
			next = head_ycache_entry->list.node.next;
			init_llist_head(&head_ycache_entry->list.head);
			head_ycache_entry->list.head.first = next;
			ycache_entry->src->entry = head_ycache_entry;
		}
	} else {
		head_ycache_entry = ycache_entry->src->entry;
		next = head_ycache_entry->list.head.first;
		/* is the first node in the list */
		if (llist_entry(next, struct ycache_entry, list.node) ==
		    ycache_entry) {
			head_ycache_entry->list.head.first = next->next;
		}
		/* not the first node in the list  */
		else {
			while (llist_entry(next->next, struct ycache_entry,
					   list.node) != ycache_entry)
				next = next->next;
			next->next = next->next->next;
		}
	}
	ycache_entry_cache_free(ycache_entry);
	spin_unlock(&ycache_host.lock);

	if (is_ephemeral(pool)) {
		atomic_dec(&ycache_curr_eph_pampd_count);
		BUG_ON(atomic_read(&ycache_curr_eph_pampd_count) < 0);
	} else {
		atomic_dec(&ycache_curr_pers_pampd_count);
		BUG_ON(atomic_read(&ycache_curr_pers_pampd_count) < 0);
	}
}

static void ycache_pampd_free_obj(struct tmem_pool *pool, struct tmem_obj *obj)
{
	pr_debug("call %s()\n", __FUNCTION__);
}

static void ycache_pampd_new_obj(struct tmem_obj *obj)
{
	pr_debug("call %s()\n", __FUNCTION__);
}

static int ycache_pampd_replace_in_obj(void *pampd, struct tmem_obj *obj)
{
	pr_debug("call %s()\n", __FUNCTION__);
	return -1;
}

/* now the page will always be stored at local host */
static bool ycache_pampd_is_remote(void *pampd)
{
	pr_debug("call %s()\n", __FUNCTION__);
	return 0;
}

static struct tmem_pamops ycache_pamops = {
    .create = ycache_pampd_create,
    .get_data = ycache_pampd_get_data,
    .get_data_and_free = ycache_pampd_get_data_and_free,
    .free = ycache_pampd_free,
    .free_obj = ycache_pampd_free_obj,
    .new_obj = ycache_pampd_new_obj,
    .replace_in_obj = ycache_pampd_replace_in_obj,
    .is_remote = ycache_pampd_is_remote,
};

/*
 * ycache shims between cleancache/frontswap ops
 * TO BE IMPLENMENT !!!
 */
static int ycache_put_page(int pool_id, struct tmem_oid *oidp, uint32_t index,
			   struct page *page)
{
	struct tmem_pool *pool;
	int ret = -1;
	unsigned long flags;

	pr_debug("call %s()\n", __FUNCTION__);
	pool = ycache_get_pool_by_id(pool_id);
	if (unlikely(pool == NULL))
		goto out;

	local_irq_save(flags);
	if (ycache_do_preload(pool, page) == 0) {
		ret = tmem_put(pool, oidp, index, (char *)(page), PAGE_SIZE, 0,
			       is_ephemeral(pool));
		if (ret < 0) {
			if (is_ephemeral(pool))
				ycache_failed_eph_puts++;
			else
				ycache_failed_pers_puts++;
		}
	} else {
		ycache_put_to_flush++;
		if (atomic_read(&pool->obj_count) > 0)
			/* the put fails whether the flush succeeds or
			 * not */
			(void)tmem_flush_page(pool, oidp, index);
	}
	local_irq_restore(flags);
	ycache_put_pool(pool);
out:
	return ret;
}

static int ycache_get_page(int pool_id, struct tmem_oid *oidp, uint32_t index,
			   struct page *page)
{
	struct tmem_pool *pool;
	int ret = -1;
	unsigned long flags;
	size_t size = PAGE_SIZE;

	//	pr_debug("call %s()\n", __FUNCTION__);
	local_irq_save(flags);
	pool = ycache_get_pool_by_id(pool_id);
	if (likely(pool != NULL)) {
		if (atomic_read(&pool->obj_count) > 0)
			ret = tmem_get(pool, oidp, index, (char *)(page), &size,
				       0, is_ephemeral(pool));
		ycache_put_pool(pool);
	}
	local_irq_restore(flags);
	return ret;
}

static int ycache_flush_page(int pool_id, struct tmem_oid *oidp, uint32_t index)
{
	struct tmem_pool *pool;
	int ret = -1;
	unsigned long flags;

	//	pr_debug("call %s()\n", __FUNCTION__);
	ycache_flush_total++;
	local_irq_save(flags);
	pool = ycache_get_pool_by_id(pool_id);
	if (likely(pool != NULL)) {
		if (atomic_read(&pool->obj_count) > 0)
			ret = tmem_flush_page(pool, oidp, index);
		ycache_put_pool(pool);
	}
	local_irq_restore(flags);
	if (ret >= 0)
		ycache_flush_found++;
	return ret;
}

static int ycache_flush_inode(int pool_id, struct tmem_oid *oidp)
{
	struct tmem_pool *pool;
	int ret = -1;
	unsigned long flags;

	//	pr_debug("call %s()\n", __FUNCTION__);

	ycache_flobj_total++;
	local_irq_save(flags);
	pool = ycache_get_pool_by_id(pool_id);
	if (likely(pool != NULL)) {
		if (atomic_read(&pool->obj_count) > 0)
			ret = tmem_flush_object(pool, oidp);
		ycache_put_pool(pool);
	}
	local_irq_restore(flags);
	if (ret >= 0)
		ycache_flobj_found++;
	return ret;
}

static int ycache_flush_fs(int pool_id)
{
	struct tmem_pool *pool = NULL;
	int ret = -1;

	pr_debug("call %s()\n", __FUNCTION__);
	if (pool_id < 0)
		goto out;

	atomic_inc(&ycache_host.refcount);
	pool = idr_find(&ycache_host.tmem_pools, pool_id);
	if (pool == NULL)
		goto out;
	idr_remove(&ycache_host.tmem_pools, pool_id);
	/* wait for pool activity on other cpus to quiesce */
	while (atomic_read(&pool->refcount) != 0)
		;
	atomic_dec(&ycache_host.refcount);
	local_bh_disable();
	ret = tmem_destroy_pool(pool);
	local_bh_enable();
	kfree(pool);
	pr_info("ycache: destroyed pool id=%d", pool_id);
out:
	return ret;
}

static int ycache_new_pool(uint32_t flags)
{
	int pool_id = -1;
	struct tmem_pool *pool;

	pr_debug("call %s()\n", __FUNCTION__);

	pool = kmalloc(sizeof(struct tmem_pool), GFP_KERNEL);
	if (pool == NULL) {
		pr_info("pool creation failed: out of memory\n");
		goto out;
	}

	pool_id = idr_alloc(&ycache_host.tmem_pools, pool, 1, 0, GFP_KERNEL);

	if (pool_id < 0) {
		pr_info("pool creation failed: error %d\n", pool_id);
		kfree(pool);
		goto out;
	}

	atomic_set(&pool->refcount, 0);
	pool->client = &ycache_host;
	pool->pool_id = pool_id;
	tmem_new_pool(pool, flags);
	pr_info("created %s tmem pool, pool_id=%d",
		flags & TMEM_POOL_PERSIST ? "persistent" : "ephemeral",
		pool_id);

	atomic_inc(&ycache_host.refcount);
out:
	return pool_id;
}

/*
 * These are "cleancache" which is used as a second-chance cache for clean
 * page cache pages; and "frontswap" which is used for swap pages
 * to avoid writes to disk.  A generic "shim" is provided here for each
 * to translate in-kernel semantics to ycache semantics.
 */

#ifdef CONFIG_CLEANCACHE
static void ycache_cleancache_put_page(int pool_id,
				       struct cleancache_filekey key,
				       pgoff_t index, struct page *page)
{
	u32 tmp_index = (u32)index;
	struct tmem_oid *oid = (struct tmem_oid *)&key;

	pr_debug("call %s()\n", __FUNCTION__);
	if (likely(tmp_index == index))
		(void)ycache_put_page(pool_id, oid, index, page);
}

static int ycache_cleancache_get_page(int pool_id,
				      struct cleancache_filekey key,
				      pgoff_t index, struct page *page)
{
	u32 tmp_index = (u32)index;
	struct tmem_oid *oid = (struct tmem_oid *)&key;
	int ret = -1;

	//	pr_debug("call %s()\n", __FUNCTION__);
	if (likely(tmp_index == index))
		ret = ycache_get_page(pool_id, oid, index, page);
	return ret;
}

static void ycache_cleancache_flush_page(int pool_id,
					 struct cleancache_filekey key,
					 pgoff_t index)
{
	u32 tmp_index = (u32)index;
	struct tmem_oid *oid = (struct tmem_oid *)&key;

	//	pr_debug("call %s()\n", __FUNCTION__);
	if (likely(tmp_index == index))
		(void)ycache_flush_page(pool_id, oid, tmp_index);
}

static void ycache_cleancache_flush_inode(int pool_id,
					  struct cleancache_filekey key)
{
	struct tmem_oid *oid = (struct tmem_oid *)&key;

	//	pr_debug("call %s()\n", __FUNCTION__);
	(void)ycache_flush_inode(pool_id, oid);
}

static void ycache_cleancache_flush_fs(int pool_id)
{
	pr_debug("call %s()\n", __FUNCTION__);
	if (pool_id >= 0)
		(void)ycache_flush_fs(pool_id);
}

static int ycache_cleancache_init_fs(size_t pagesize)
{
	BUG_ON(sizeof(struct cleancache_filekey) != sizeof(u64[3]));
	BUG_ON(pagesize != PAGE_SIZE);

	pr_debug("call %s()\n", __FUNCTION__);

	return ycache_new_pool(0);
}

/* Wait for implementation */
static int ycache_cleancache_init_shared_fs(char *uuid, size_t pagesize)
{
	pr_debug("call %s()\n", __FUNCTION__);
	BUG_ON(sizeof(struct cleancache_filekey) != sizeof(u64[3]));
	BUG_ON(pagesize != PAGE_SIZE);
	/* not implemented, use init_fs instead */
	ycache_cleancache_init_fs(pagesize);
	return 0;
}

static struct cleancache_ops ycache_cleancache_ops = {
    .put_page = ycache_cleancache_put_page,
    .get_page = ycache_cleancache_get_page,
    .invalidate_page = ycache_cleancache_flush_page,
    .invalidate_inode = ycache_cleancache_flush_inode,
    .invalidate_fs = ycache_cleancache_flush_fs,
    .init_shared_fs = ycache_cleancache_init_shared_fs,
    .init_fs = ycache_cleancache_init_fs};
/*
 * On Linux 4.1, cleancache_register_ops return int instead of
 * pointer to cleancache_ops
 */
struct cleancache_ops *ycache_cleancache_register_ops(void)
{
	return cleancache_register_ops(&ycache_cleancache_ops);
}

#endif

#ifdef CONFIG_FRONTSWAP
/* a single tmem poolid is used for all frontswap "types" (swapfiles) */
static int ycache_frontswap_poolid = -1;

/*
 * Swizzling increases objects per swaptype, increasing tmem concurrency
 * for heavy swaploads.  Later, larger nr_cpus -> larger SWIZ_BITS
 * Setting SWIZ_BITS to 27 basically reconstructs the swap entry from
 * frontswap_load(), but has side-effects. Hence using 8.
 */
#define SWIZ_BITS 8
#define SWIZ_MASK ((1 << SWIZ_BITS) - 1)
#define _oswiz(_type, _ind) ((_type << SWIZ_BITS) | (_ind & SWIZ_MASK))
#define iswiz(_ind) (_ind >> SWIZ_BITS)

static inline struct tmem_oid oswiz(unsigned type, u32 ind)
{
	struct tmem_oid oid = {.oid = {0}};
	oid.oid[0] = _oswiz(type, ind);
	return oid;
}

static int ycache_frontswap_store(unsigned type, pgoff_t offset,
				  struct page *page)
{
	u64 ind64 = (u64)offset;
	u32 ind = (u32)offset;
	struct tmem_oid oid = oswiz(type, ind);
	int ret = -1;

	BUG_ON(!PageLocked(page));
	if (likely(ind64 == ind))
		ret = ycache_put_page(ycache_frontswap_poolid, &oid, iswiz(ind),
				      page);

	return ret;
}

/* returns 0 if the page was successfully gotten from frontswap, -1 if
 * was not present (should never happen!) */
static int ycache_frontswap_load(unsigned type, pgoff_t offset,
				 struct page *page)
{
	u64 ind64 = (u64)offset;
	u32 ind = (u32)offset;
	struct tmem_oid oid = oswiz(type, ind);
	int ret = -1;

	BUG_ON(!PageLocked(page));
	if (likely(ind64 == ind))
		ret = ycache_get_page(ycache_frontswap_poolid, &oid, iswiz(ind),
				      page);
	return ret;
}

/* flush a single page from frontswap */
static void ycache_frontswap_flush_page(unsigned type, pgoff_t offset)
{
	u64 ind64 = (u64)offset;
	u32 ind = (u32)offset;
	struct tmem_oid oid = oswiz(type, ind);

	if (likely(ind64 == ind))
		(void)ycache_flush_page(ycache_frontswap_poolid, &oid,
					iswiz(ind));
}

/* flush all pages from the passed swaptype */
static void ycache_frontswap_flush_area(unsigned type)
{
	struct tmem_oid oid;
	int ind;

	for (ind = SWIZ_MASK; ind >= 0; ind--) {
		oid = oswiz(type, ind);
		(void)ycache_flush_inode(ycache_frontswap_poolid, &oid);
	}
}

static void ycache_frontswap_init(unsigned ignored)
{
	/* a single tmem poolid is used for all frontswap "types" (swapfiles) */
	if (ycache_frontswap_poolid < 0)
		ycache_frontswap_poolid = ycache_new_pool(TMEM_POOL_PERSIST);
}

static struct frontswap_ops ycache_frontswap_ops = {
    .store = ycache_frontswap_store,
    .load = ycache_frontswap_load,
    .invalidate_page = ycache_frontswap_flush_page,
    .invalidate_area = ycache_frontswap_flush_area,
    .init = ycache_frontswap_init};

struct frontswap_ops *ycache_frontswap_register_ops(void)
{
	struct frontswap_ops *old_ops =
	    frontswap_register_ops(&ycache_frontswap_ops);

	return old_ops;
}
#endif

/*********************************
* debugfs functions
**********************************/
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>

static struct dentry *ycache_debugfs_root;

static int __init ycache_debugfs_init(void)
{
	pr_debug("call %s()\n", __FUNCTION__);
	if (!debugfs_initialized())
		return -ENODEV;

	ycache_debugfs_root = debugfs_create_dir("ycache", NULL);
	if (!ycache_debugfs_root)
		return -ENOMEM;

	debugfs_create_atomic_t("total_pages", S_IRUGO, ycache_debugfs_root,
				&ycache_total_pages);
	debugfs_create_atomic_t("duplicate_pages", S_IRUGO, ycache_debugfs_root,
				&ycache_duplicate_pages);
	debugfs_create_u64("yentry_kmemcache_fail", S_IRUGO,
			   ycache_debugfs_root, &ycache_yentry_kmemcache_fail);
	debugfs_create_u64("pentry_kmemcache_fail", S_IRUGO,
			   ycache_debugfs_root, &ycache_pentry_kmemcache_fail);
	debugfs_create_u64("md5_fail", S_IRUGO, ycache_debugfs_root,
			   &ycache_md5_fail);
	debugfs_create_u64("flush_total", S_IRUGO, ycache_debugfs_root,
			   &ycache_flush_total);
	debugfs_create_u64("flush_found", S_IRUGO, ycache_debugfs_root,
			   &ycache_flush_found);
	debugfs_create_u64("flobj_total", S_IRUGO, ycache_debugfs_root,
			   &ycache_flobj_total);
	debugfs_create_u64("flobj_found", S_IRUGO, ycache_debugfs_root,
			   &ycache_flobj_found);
	debugfs_create_u64("failed_eph_puts", S_IRUGO, ycache_debugfs_root,
			   &ycache_failed_eph_puts);
	debugfs_create_u64("failed_pers_puts", S_IRUGO, ycache_debugfs_root,
			   &ycache_failed_pers_puts);
	debugfs_create_u64("failed_get_free_pages", S_IRUGO,
			   ycache_debugfs_root, &ycache_failed_get_free_pages);
	debugfs_create_u64("ycache_failed_alloc", S_IRUGO, ycache_debugfs_root,
			   &ycache_failed_alloc);
	debugfs_create_u64("put_to_flush", S_IRUGO, ycache_debugfs_root,
			   &ycache_put_to_flush);
	debugfs_create_atomic_t("curr_obj_count", S_IRUGO, ycache_debugfs_root,
				&ycache_curr_obj_count);
	debugfs_create_u64("curr_obj_count_max", S_IRUGO, ycache_debugfs_root,
			   &ycache_curr_obj_count_max);
	debugfs_create_atomic_t("curr_objnode_count", S_IRUGO,
				ycache_debugfs_root,
				&ycache_curr_objnode_count);
	debugfs_create_u64("curr_objnode_count_max", S_IRUGO,
			   ycache_debugfs_root, &ycache_curr_objnode_count_max);

	return 0;
}

static void __exit ycache_debugfs_exit(void)
{
	pr_debug("call %s()\n", __FUNCTION__);
	debugfs_remove_recursive(ycache_debugfs_root);
}
#else
static int __init ycache_debugfs_init(void)
{
	pr_debug("call %s()\n", __FUNCTION__);
	return 0;
}

static void __exit ycache_debugfs_exit(void)
{
	pr_debug("call %s()\n", __FUNCTION__);
}
#endif

/*
 * ycache initialization
 */

static int __init ycache_init(void)
{
#ifdef CONFIG_CLEANCACHE
	struct cleancache_ops *old_cleancache_ops;
#endif
#ifdef CONFIG_FRONTSWAP
	struct frontswap_ops *old_frontswap_ops;
#endif

	pr_info("loading ycache\n");
	init_ycache_host();
	tmem_register_hostops(&ycache_hostops);
	tmem_register_pamops(&ycache_pamops);
	if (ycache_objnode_cache_create()) {
		pr_err("ycache_objnode_cache creation failed\n");
		goto error;
	}
	if (ycache_obj_cache_create()) {
		pr_err("ycache_obj_cache creation failed\n");
		goto objfail;
	}
	if (page_entry_cache_create()) {
		pr_err("page_entry_cache creation failed\n");
		goto p_cachefail;
	}
	if (ycache_entry_cache_create()) {
		pr_err("ycache_entry_cache creation failed\n");
		goto y_cachefail;
	}

#ifdef CONFIG_CLEANCACHE
	old_cleancache_ops = ycache_cleancache_register_ops();
	pr_info("cleancache enabled using kernel transcendent memory\n");
	if (old_cleancache_ops && old_cleancache_ops->init_fs != NULL)
		pr_warning("cleancache_ops overridden");
#endif
#ifdef CONFIG_FRONTSWAP
	old_frontswap_ops = ycache_frontswap_register_ops();
	pr_info("frontswap enabled using kernel transcendent memory\n");
	if (old_frontswap_ops && old_frontswap_ops->init != NULL)
		pr_warning("frontswap_ops overridden\n");
#endif
	if (ycache_debugfs_init())
		pr_warn("debugfs initialization failed\n");

	pr_info("ycache loaded without errors \n");
	return 0;
y_cachefail:
	page_entry_cache_destroy();
p_cachefail:
	ycache_obj_cache_destroy();
objfail:
	ycache_objnode_cache_destroy();
error:
	return -ENOMEM;
}

/* must be late so crypto has time to come up */
late_initcall(ycache_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Eric Zhang <gd.yi@139.com>");
MODULE_DESCRIPTION("Deduplicate pages evicted from page cache ");
