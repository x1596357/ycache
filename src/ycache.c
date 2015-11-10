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
#include <linux/version.h>
#include "tmem.h"

#ifdef CONFIG_CLEANCACHE
#include <linux/cleancache.h>
#endif

#define YCACHE_GFP_MASK                                                        \
	(__GFP_FS | __GFP_NORETRY | __GFP_NOWARN | __GFP_NOMEMALLOC)
#define MAX_YCACHE_TREES 1024

/* Total pages used for storage */
static atomic_t ycache_used_pages = ATOMIC_INIT(0);
/* Total pages got in the module */
static atomic_t ycache_total_pages = ATOMIC_INIT(0);

/* Some of the statistics below are not protected from concurrent access for
 * performance reasons so they may not be a 100% accurate.  However,
 * they do provide useful information on roughly how many times a
 * certain event is occurring.
*/
/* Store failed because the ycache_entry could not be allocated (rare) */
static u64 ycache_entry_fail;
/* Get MD5 of page failed */
static u64 ycache_md5_fail;
/* MD5 collision times*/
static u64 ycache_md5_collision;
/* Counters for debugging */
static u64 ycache_failed_get_free_pages;
static u64 ycache_failed_alloc;
static u64 ycache_put_to_flush;
/* Useful stats not collected by cleancache */
static u64 ycache_flush_total;
static u64 ycache_flush_found;
static u64 ycache_flobj_total;
static u64 ycache_flobj_found;
static u64 ycache_failed_puts;
/* tmem statistics */
static atomic_t ycache_curr_eph_pampd_count = ATOMIC_INIT(0);
static unsigned long ycache_curr_eph_pampd_count_max;
static atomic_t ycache_curr_obj_count = ATOMIC_INIT(0);
static u64 ycache_curr_obj_count_max;
static atomic_t ycache_curr_objnode_count = ATOMIC_INIT(0);
static u64 ycache_curr_objnode_count_max;

/*********************************
* data structures
**********************************/
/*
 * struct ycache_tree
 *
 * rbroot - red-black tree root
 * lock   - this lock protect the rbtree and the refcount in ycache_entry
 */
struct ycache_tree {
	struct rb_root rbroot;
	spinlock_t lock;
};

static struct ycache_tree ycache_trees[MAX_YCACHE_TREES];

static inline struct ycache_tree *get_ycache_tree(uint32_t index)
{
	return &ycache_trees[index % MAX_YCACHE_TREES];
}
/*
 * struct ycache_entry
 *
 * page   - pointer to a page, this is where data is actually stored
 * rbnode - red-black tree node
 * hash   - contains the hash value. Since we use array to store it, we
 * 	    need to hardcode the size.
 * refcount - the number of reference to this page. When a ycache_entry
 * 	      is created, refcount is 1. When the page is deduplicated,
 * 	      refcount increase by 1. When using this ycache_entry refcount
 * 	      increase by 1. And after ycache_entry is put back, refcount
 * 	      decrease by 1. When this page is flushed, refcount decrease
 * 	      by 1. Upon refcount drop to 0, this ycache_entry should be freed.
 */
struct ycache_entry {
	struct page *page;
	struct rb_node rbnode;
	u8 hash[MD5_DIGEST_SIZE];
	int refcount;
};

/*********************************
* ycache_entry functions
**********************************/
static struct kmem_cache *ycache_entry_cache;

static int __init ycache_entry_cache_create(void)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	ycache_entry_cache = KMEM_CACHE(ycache_entry, 0);
	return ycache_entry_cache == NULL;
}

__attribute__((unused)) static void __init ycache_entry_cache_destroy(void)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	kmem_cache_destroy(ycache_entry_cache);
}

/* forward reference */
static void ycache_entry_cache_free(struct ycache_entry *);

static struct ycache_entry *ycache_entry_cache_alloc(gfp_t gfp)
{
	struct ycache_entry *entry;

	// pr_debug("call %s()\n", __FUNCTION__);
	entry = kmem_cache_alloc(ycache_entry_cache, gfp);
	if (likely(entry != NULL)) {
		/* alloc page*/
		entry->page = alloc_page(gfp | __GFP_HIGHMEM);
		if (likely(entry->page != NULL)) {
			entry->refcount = 1;
			RB_CLEAR_NODE(&entry->rbnode);
			atomic_inc(&ycache_used_pages);
			return entry;
		} else {
			ycache_entry_cache_free(entry);
			ycache_entry_fail++;
			ycache_failed_get_free_pages++;
			return NULL;
		}
	} else {
		ycache_entry_fail++;
		return NULL;
	}
}

static void ycache_entry_cache_free(struct ycache_entry *entry)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	BUG_ON(entry == NULL);
	if (likely(entry->page != NULL)) {
		__free_page(entry->page);
		atomic_dec(&ycache_used_pages);
	}
	kmem_cache_free(ycache_entry_cache, entry);
}

/*********************************
* ycache_entry rbtree functions
**********************************/
static struct ycache_entry *ycache_rb_search(struct rb_root *root, u8 *hash)
{
	struct rb_node *node = root->rb_node;
	struct ycache_entry *entry;
	int result;

	// pr_debug("call %s()\n", __FUNCTION__);
	while (node) {
		entry = rb_entry(node, struct ycache_entry, rbnode);
		result = memcmp(entry->hash, hash, MD5_DIGEST_SIZE);
		if (result > 0)
			node = node->rb_left;
		else if (result < 0)
			node = node->rb_right;
		else
			return entry;
	}
	return NULL;
}

/*
 * In the case that a entry with the same values is found, a pointer to
 * the existing entry is stored in dupentry and the function returns
 * -EEXIST
 */
static int ycache_rb_insert(struct rb_root *root, struct ycache_entry *entry,
			    struct ycache_entry **dupentry)
{
	struct rb_node **link = &root->rb_node, *parent = NULL;
	struct ycache_entry *tmp_entry;
	int result;

	// pr_debug("call %s()\n", __FUNCTION__);
	while (*link) {
		parent = *link;
		tmp_entry = rb_entry(parent, struct ycache_entry, rbnode);
		result = memcmp(tmp_entry->hash, entry->hash, MD5_DIGEST_SIZE);
		if (result > 0)
			link = &(*link)->rb_left;
		else if (result < 0)
			link = &(*link)->rb_right;
		else {
			*dupentry = tmp_entry;
			return -EEXIST;
		}
	}
	rb_link_node(&entry->rbnode, parent, link);
	rb_insert_color(&entry->rbnode, root);
	return 0;
}

static void ycache_rb_erase(struct rb_root *root, struct ycache_entry *entry)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	if (likely(!RB_EMPTY_NODE(&entry->rbnode))) {
		rb_erase(&entry->rbnode, root);
		RB_CLEAR_NODE(&entry->rbnode);
	}
}

/* caller must hold the tree lock */
static inline void ycache_entry_get(struct ycache_entry *entry)
{
	entry->refcount++;
}

/* caller must hold the tree lock
 * remove from the tree and free it, if nobody reference the entry
 */
static void ycache_entry_put(struct ycache_tree *tree,
			     struct ycache_entry *entry)
{
	int refcount = --entry->refcount;

	BUG_ON(refcount < 0);
	if (refcount == 0) {
		ycache_rb_erase(&tree->rbroot, entry);
		ycache_entry_cache_free(entry);
	}
}

/* caller must hold the tree lock */
static struct ycache_entry *ycache_entry_find_get(struct rb_root *root,
						  u8 *hash)
{
	struct ycache_entry *entry = NULL;

	entry = ycache_rb_search(root, hash);
	if (entry)
		ycache_entry_get(entry);

	return entry;
}

/*
 * page_to_md5 - caculate md5 message digest for a page
 *
 * @src:    The start virtual address of the message
 * @result: Somewhere used to store the md5 value, need 128 bit.
 *          (see include/crypto/md5.h - MD5_DIGEST_SIZE)
 *
 * Return:  0 if the caculation is successful, <0 if an error was
 * 			occurred
 *
 */
static int page_to_md5(const void *src, u8 *result)
{
	struct hash_desc desc;
	struct scatterlist sg;
	int ret = 0;

	// pr_debug("call %s()\n", __FUNCTION__);
	sg_init_one(&sg, (u8 *)src, PAGE_SIZE);
	desc.tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);
	/* fail to allocate a cipher handle */
	if (unlikely(IS_ERR(desc.tfm))) {
		ret = -EINVAL;
		goto out;
	}

	desc.flags = CRYPTO_TFM_REQ_MAY_SLEEP;
	ret = crypto_hash_init(&desc);
	if (unlikely(ret))
		goto out;
	ret = crypto_hash_update(&desc, &sg, PAGE_SIZE);
	if (unlikely(ret))
		goto out;
	ret = crypto_hash_final(&desc, result);
	if (unlikely(ret))
		goto out;
out:
	crypto_free_hash(desc.tfm);
	if (unlikely(ret != 0))
		ycache_md5_fail++;
	return ret;
}

static int is_page_same(struct page *p1, struct page *p2)
{
	u8 *src, *dst;
	int ret;

	// pr_debug("call %s()\n", __FUNCTION__);
	src = kmap_atomic(p1);
	dst = kmap_atomic(p2);
	ret = memcmp(src, dst, PAGE_SIZE);
	kunmap_atomic(dst);
	kunmap_atomic(src);
	return ret == 0;
}

/* ycache structure */
struct ycache_client {
	struct idr tmem_pools;
};

static struct ycache_client *ycache_host = NULL;

static __init int init_ycache_host(void)
{
	int i;
	// pr_debug("call %s()\n", __FUNCTION__);
	if (unlikely(ycache_host != NULL)) {
		return 0;
	} else {
		ycache_host = (struct ycache_client *)kmalloc(
		    sizeof(struct ycache_client), GFP_KERNEL);
		if (ycache_host == NULL)
			return -ENOMEM;
		idr_init(&ycache_host->tmem_pools);
		for (i = 0; i < MAX_YCACHE_TREES; i++) {
			ycache_trees[i].rbroot = RB_ROOT;
			spin_lock_init(&ycache_trees[i].lock);
		}
	}
	return 0;
}

/*
 * Tmem operations assume the pool_id implies the invoking client.
 * ycache only has one client (the kernel itself).
 */
static struct tmem_pool *ycache_get_pool_by_id(uint16_t pool_id)
{
	struct tmem_pool *pool = NULL;

	// pr_debug("call %s()\n", __FUNCTION__);
	pool = idr_find(&ycache_host->tmem_pools, pool_id);
	if (likely(pool))
		atomic_inc(&pool->refcount);
	return pool;
}

static void ycache_put_pool(struct tmem_pool *pool)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	BUG_ON(pool == NULL);
	atomic_dec(&pool->refcount);
}

static struct kmem_cache *ycache_objnode_cache;

static int __init ycache_objnode_cache_create(void)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	ycache_objnode_cache = KMEM_CACHE(tmem_objnode, 0);
	return ycache_objnode_cache == NULL;
}

static void __init ycache_objnode_cache_destroy(void)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	kmem_cache_destroy(ycache_objnode_cache);
}

static struct kmem_cache *ycache_obj_cache;

static int __init ycache_obj_cache_create(void)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	ycache_obj_cache = KMEM_CACHE(tmem_obj, 0);
	return ycache_obj_cache == NULL;
}

static void __init ycache_obj_cache_destroy(void)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	kmem_cache_destroy(ycache_obj_cache);
}

/* to avoid some memory allocation recursion (e.g. due to direct reclaim) */
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

	// pr_debug("call %s()\n", __FUNCTION__);
	if (unlikely(ycache_objnode_cache == NULL))
		goto out;
	if (unlikely(ycache_obj_cache == NULL))
		goto out;

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

/* ycache implementation for tmem host ops */

static struct tmem_objnode *ycache_objnode_alloc(struct tmem_pool *pool)
{
	struct tmem_objnode *objnode = NULL;
	unsigned long count;
	struct ycache_preload *kp;

	// pr_debug("call %s()\n", __FUNCTION__);
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
	// pr_debug("call %s()\n", __FUNCTION__);
	atomic_dec(&ycache_curr_objnode_count);
	BUG_ON(atomic_read(&ycache_curr_objnode_count) < 0);
	kmem_cache_free(ycache_objnode_cache, objnode);
}

static struct tmem_obj *ycache_obj_alloc(struct tmem_pool *pool)
{
	struct tmem_obj *obj = NULL;
	unsigned long count;
	struct ycache_preload *kp;

	// pr_debug("call %s()\n", __FUNCTION__);
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
	// pr_debug("call %s()\n", __FUNCTION__);
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

/* use tmem to manage the relation of page address and ycache_entry.
 * pampd is (void *)(struct ycache_entry *)
 */

static void *ycache_pampd_create(char *data, size_t size, bool raw, int eph,
				 struct tmem_pool *pool, struct tmem_oid *oid,
				 uint32_t index)
{
	void *pampd = NULL;
	struct page *page;
	struct ycache_entry *entry;
	struct ycache_entry *dupentry;
	struct ycache_tree *ycache_tree;
	int result;
	unsigned long count;
	u8 hash[MD5_DIGEST_SIZE];
	u8 *src, *dst;

	// pr_debug("call %s()\n", __FUNCTION__);

	BUG_ON(data == NULL);
	page = (struct page *)data;
	/* calculating MD5 may sleep, thus have to use kmap */
	src = kmap(page);
	page_to_md5(src, hash);
	kunmap(page);

	ycache_tree = get_ycache_tree(index);
	spin_lock(&ycache_tree->lock);
	entry = ycache_entry_find_get(&ycache_tree->rbroot, hash);
	/* hash not exists */
	if (likely(entry == NULL)) {
		spin_unlock(&ycache_tree->lock);

		entry = ycache_entry_cache_alloc(YCACHE_GFP_MASK);
		if (unlikely(entry == NULL)) {
			goto reject;
		}
		/* copy page */
		src = kmap_atomic(page);
		dst = kmap_atomic(entry->page);
		copy_page(dst, src);
		kunmap_atomic(dst);
		kunmap_atomic(src);
		/* copy hash values */
		memcpy(entry->hash, hash, MD5_DIGEST_SIZE);

		spin_lock(&ycache_tree->lock);
		result =
		    ycache_rb_insert(&ycache_tree->rbroot, entry, &dupentry);
		spin_unlock(&ycache_tree->lock);
		// this rarely happens, it has to be taken cared of (reject)
		// should it happen
		if (unlikely(result == -EEXIST)) {
			ycache_entry_cache_free(entry);
		} else {
			atomic_inc(&ycache_total_pages);
			pampd = (void *)entry;
		}
	}
	/* hash exists, compare bit by bit */
	else if (likely(is_page_same(entry->page, page))) {
		/* deduplicated one page, refcount++ */
		entry->refcount++;
		ycache_entry_put(ycache_tree, entry);
		spin_unlock(&ycache_tree->lock);
		atomic_inc(&ycache_total_pages);
		pampd = (void *)entry;
	}
	/* hash is the same but data is not */
	else {
		ycache_md5_collision++;
		ycache_entry_put(ycache_tree, entry);
		spin_unlock(&ycache_tree->lock);
	}

	if (likely(pampd != NULL)) {
		count = atomic_inc_return(&ycache_curr_eph_pampd_count);
		if (count > ycache_curr_eph_pampd_count_max)
			ycache_curr_eph_pampd_count_max = count;
	}
reject:
	return pampd;
}

static int ycache_pampd_get_data(char *data, size_t *bufsize, bool raw,
				 void *pampd, struct tmem_pool *pool,
				 struct tmem_oid *oid, uint32_t index)
{
	struct ycache_entry *entry;
	struct ycache_tree *ycache_tree;
	u8 *src, *dst;
	int ret = -EINVAL;

	// pr_debug("call %s()\n", __FUNCTION__);
	// BUG_ON(is_ephemeral(pool));
	// BUG_ON(pampd == NULL);
	BUG_ON(data == NULL);

	entry = (struct ycache_entry *)pampd;
	if (entry) {
		ycache_tree = get_ycache_tree(index);
		spin_lock(&ycache_tree->lock);
		ycache_entry_get(entry);
		spin_unlock(&ycache_tree->lock);
		src = kmap_atomic(entry->page);
		dst = kmap_atomic((struct page *)data);
		copy_page(dst, src);
		kunmap_atomic(dst);
		kunmap_atomic(src);
		spin_lock(&ycache_tree->lock);
		ycache_entry_put(ycache_tree, entry);
		spin_unlock(&ycache_tree->lock);
	} else {
		goto out;
	}

	ret = 0;
out:
	return ret;
}

static int ycache_pampd_get_data_and_free(char *data, size_t *bufsize, bool raw,
					  void *pampd, struct tmem_pool *pool,
					  struct tmem_oid *oid, uint32_t index)
{
	struct ycache_entry *entry;
	struct ycache_tree *ycache_tree;
	u8 *src, *dst;

	// pr_debug("call %s()\n", __FUNCTION__);
	BUG_ON(!is_ephemeral(pool));
	BUG_ON(pampd == NULL);
	BUG_ON(data == NULL);

	ycache_tree = get_ycache_tree(index);
	entry = (struct ycache_entry *)pampd;
	src = kmap_atomic(entry->page);
	dst = kmap_atomic((struct page *)data);
	copy_page(dst, src);
	kunmap_atomic(dst);
	kunmap_atomic(src);

	spin_lock(&ycache_tree->lock);
	/* we ignored getting and dropping local reference */
	/* drop one reference upon creation or deduplication */
	ycache_entry_put(ycache_tree, entry);
	spin_unlock(&ycache_tree->lock);

	atomic_dec(&ycache_total_pages);
	atomic_dec(&ycache_curr_eph_pampd_count);
	BUG_ON(atomic_read(&ycache_curr_eph_pampd_count) < 0);

	return 0;
}

/*
 * free the pampd and remove it from any ycache lists
 * pampd must no longer be pointed to from any tmem data structures!
 */
static void ycache_pampd_free(void *pampd, struct tmem_pool *pool,
			      struct tmem_oid *oid, uint32_t index)
{
	struct ycache_entry *entry;
	struct ycache_tree *ycache_tree;

	// pr_debug("call %s()\n", __FUNCTION__);
	ycache_tree = get_ycache_tree(index);
	entry = (struct ycache_entry *)pampd;
	spin_lock(&ycache_tree->lock);
	/* drop one reference upon creation or deduplication */
	ycache_entry_put(ycache_tree, entry);
	spin_unlock(&ycache_tree->lock);

	atomic_dec(&ycache_total_pages);
	atomic_dec(&ycache_curr_eph_pampd_count);
	BUG_ON(atomic_read(&ycache_curr_eph_pampd_count) < 0);
}

static void ycache_pampd_free_obj(struct tmem_pool *pool, struct tmem_obj *obj)
{
	// pr_debug("call %s()\n", __FUNCTION__);
}

static void ycache_pampd_new_obj(struct tmem_obj *obj)
{
	// pr_debug("call %s()\n", __FUNCTION__);
}

static int ycache_pampd_replace_in_obj(void *pampd, struct tmem_obj *obj)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	return -1;
}

/* now the page will always be stored at local host */
static bool ycache_pampd_is_remote(void *pampd)
{
	// pr_debug("call %s()\n", __FUNCTION__);
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

/* These are "cleancache" which is used as a second-chance cache for clean
 * page cache pages;
 */

#ifdef CONFIG_CLEANCACHE
static void ycache_cleancache_put_page(int pool_id,
				       struct cleancache_filekey key,
				       pgoff_t index, struct page *page)
{
	struct tmem_pool *pool;
	struct tmem_oid *oid = (struct tmem_oid *)&key;
	u32 tmp_index = (u32)index;
	int ret = -1;

	// pr_debug("call %s()\n", __FUNCTION__);
	if (unlikely(tmp_index != index))
		return;

	pool = ycache_get_pool_by_id(pool_id);
	if (unlikely(pool == NULL))
		return;

	// local_irq_save(flags);
	preempt_disable();
	if (likely(ycache_do_preload(pool, page) == 0)) {
		ret = tmem_put(pool, oid, index, (char *)(page), PAGE_SIZE, 0,
			       is_ephemeral(pool));
		if (unlikely(ret < 0)) {
			ycache_failed_puts++;
		}
	} else {
		ycache_put_to_flush++;
		if (atomic_read(&pool->obj_count) > 0)
			/* the put fails whether the flush succeeds or
			 * not */
			(void)tmem_flush_page(pool, oid, index);
	}
	preempt_enable();
	// local_irq_restore(flags);
	ycache_put_pool(pool);
}

static int ycache_cleancache_get_page(int pool_id,
				      struct cleancache_filekey key,
				      pgoff_t index, struct page *page)
{
	struct tmem_pool *pool;
	struct tmem_oid *oid = (struct tmem_oid *)&key;
	u32 tmp_index = (u32)index;
	size_t size = PAGE_SIZE;
	int ret = -1;
	// unsigned long flags;

	// pr_debug("call %s()\n", __FUNCTION__);
	if (unlikely(tmp_index != index))
		goto out;

	// local_irq_save(flags);
	pool = ycache_get_pool_by_id(pool_id);
	if (likely(pool != NULL)) {
		if (atomic_read(&pool->obj_count) > 0)
			ret = tmem_get(pool, oid, index, (char *)(page), &size,
				       0, is_ephemeral(pool));
		ycache_put_pool(pool);
	}
// local_irq_restore(flags);
out:
	return ret;
}

static void ycache_cleancache_flush_page(int pool_id,
					 struct cleancache_filekey key,
					 pgoff_t index)
{
	struct tmem_pool *pool;
	struct tmem_oid *oid = (struct tmem_oid *)&key;
	u32 tmp_index = (u32)index;
	int ret = -1;
	// unsigned long flags;

	// pr_debug("call %s()\n", __FUNCTION__);
	if (unlikely(tmp_index != index))
		return;

	ycache_flush_total++;
	// local_irq_save(flags);
	pool = ycache_get_pool_by_id(pool_id);
	if (likely(pool != NULL)) {
		if (atomic_read(&pool->obj_count) > 0)
			ret = tmem_flush_page(pool, oid, index);
		ycache_put_pool(pool);
	}
	// local_irq_restore(flags);
	if (ret >= 0)
		ycache_flush_found++;
}

static void ycache_cleancache_flush_inode(int pool_id,
					  struct cleancache_filekey key)
{
	struct tmem_pool *pool;
	struct tmem_oid *oid = (struct tmem_oid *)&key;
	int ret = -1;
	// unsigned long flags;

	// pr_debug("call %s()\n", __FUNCTION__);
	ycache_flobj_total++;
	// local_irq_save(flags);
	pool = ycache_get_pool_by_id(pool_id);
	if (likely(pool != NULL)) {
		if (atomic_read(&pool->obj_count) > 0)
			ret = tmem_flush_object(pool, oid);
		ycache_put_pool(pool);
	}
	// local_irq_restore(flags);
	if (ret >= 0)
		ycache_flobj_found++;
}

static void ycache_cleancache_flush_fs(int pool_id)
{
	struct tmem_pool *pool = NULL;

	// pr_debug("call %s()\n", __FUNCTION__);
	if (unlikely(pool_id < 0))
		return;

	pool = idr_find(&ycache_host->tmem_pools, pool_id);
	if (pool == NULL)
		return;
	idr_remove(&ycache_host->tmem_pools, pool_id);
	/* wait for pool activity on other cpus to quiesce */
	while (atomic_read(&pool->refcount) != 0)
		;
	local_bh_disable();
	tmem_destroy_pool(pool);
	local_bh_enable();
	kfree(pool);
	pr_info("destroyed pool id=%d", pool_id);
}

static int ycache_cleancache_init_fs(size_t pagesize)
{
	struct tmem_pool *pool;
	int pool_id = -1;

	// pr_debug("call %s()\n", __FUNCTION__);
	BUG_ON(sizeof(struct cleancache_filekey) != sizeof(u64[3]));
	BUG_ON(pagesize != PAGE_SIZE);

	pool = kmalloc(sizeof(struct tmem_pool), GFP_KERNEL);
	if (unlikely(pool == NULL)) {
		pr_warn("pool creation failed: out of memory\n");
		goto out;
	}

	pool_id = idr_alloc(&ycache_host->tmem_pools, pool, 0, 0, GFP_KERNEL);

	if (unlikely(pool_id < 0)) {
		pr_warn("pool creation failed: error %d\n", pool_id);
		kfree(pool);
		goto out;
	}

	atomic_set(&pool->refcount, 0);
	pool->client = ycache_host;
	pool->pool_id = pool_id;
	tmem_new_pool(pool, 0);
	pr_info("created ephemeral tmem pool, pool_id=%d", pool_id);
out:
	return pool_id;
}

/* Wait for implementation */
static int ycache_cleancache_init_shared_fs(char *uuid, size_t pagesize)
{
	// pr_debug("call %s()\n", __FUNCTION__);
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

static inline __init void ycache_cleancache_register_ops(void)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	cleancache_register_ops(&ycache_cleancache_ops);
}

#endif

static int ycache_cpu_notifier(struct notifier_block *nb, unsigned long action,
			       void *pcpu)
{
	int cpu = (long)pcpu;
	struct ycache_preload *kp;

	switch (action) {
	case CPU_DEAD:
	case CPU_UP_CANCELED:
		kp = &per_cpu(ycache_preloads, cpu);
		while (kp->nr) {
			kmem_cache_free(ycache_objnode_cache,
					kp->objnodes[kp->nr - 1]);
			kp->objnodes[kp->nr - 1] = NULL;
			kp->nr--;
		}
		if (kp->obj) {
			kmem_cache_free(ycache_obj_cache, kp->obj);
			kp->obj = NULL;
		}
		break;
	default:
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block ycache_cpu_notifier_block = {
    .notifier_call = ycache_cpu_notifier};

/*********************************
* debugfs functions
**********************************/
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>

static struct dentry *ycache_debugfs_root;

static int __init ycache_debugfs_init(void)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	if (!debugfs_initialized())
		return -ENODEV;

	ycache_debugfs_root = debugfs_create_dir("ycache", NULL);
	if (!ycache_debugfs_root)
		return -ENOMEM;

	debugfs_create_atomic_t("used_pages", S_IRUGO, ycache_debugfs_root,
				&ycache_used_pages);
	debugfs_create_atomic_t("total_pages", S_IRUGO, ycache_debugfs_root,
				&ycache_total_pages);
	debugfs_create_u64("entry_fail", S_IRUGO, ycache_debugfs_root,
			   &ycache_entry_fail);
	debugfs_create_u64("md5_fail", S_IRUGO, ycache_debugfs_root,
			   &ycache_md5_fail);
	debugfs_create_u64("md5_collision", S_IRUGO, ycache_debugfs_root,
			   &ycache_md5_collision);
	debugfs_create_u64("flush_total", S_IRUGO, ycache_debugfs_root,
			   &ycache_flush_total);
	debugfs_create_u64("flush_found", S_IRUGO, ycache_debugfs_root,
			   &ycache_flush_found);
	debugfs_create_u64("flobj_total", S_IRUGO, ycache_debugfs_root,
			   &ycache_flobj_total);
	debugfs_create_u64("flobj_found", S_IRUGO, ycache_debugfs_root,
			   &ycache_flobj_found);
	debugfs_create_u64("failed_puts", S_IRUGO, ycache_debugfs_root,
			   &ycache_failed_puts);
	debugfs_create_u64("failed_get_free_pages", S_IRUGO,
			   ycache_debugfs_root, &ycache_failed_get_free_pages);
	debugfs_create_u64("failed_alloc", S_IRUGO, ycache_debugfs_root,
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

__attribute__((unused)) static void __exit ycache_debugfs_exit(void)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	debugfs_remove_recursive(ycache_debugfs_root);
}
#else
static int __init ycache_debugfs_init(void)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	return 0;
}

static void __exit ycache_debugfs_exit(void)
{
	// pr_debug("call %s()\n", __FUNCTION__);
}
#endif

/*
 * ycache initialization
 */

static int __init ycache_init(void)
{
	pr_info("loading\n");
	if (unlikely(init_ycache_host())) {
		pr_err("ycache host creation failed\n");
		goto error;
	}
	tmem_register_hostops(&ycache_hostops);
	tmem_register_pamops(&ycache_pamops);
	if (unlikely(register_cpu_notifier(&ycache_cpu_notifier_block))) {
		pr_err("can't register cpu notifier\n");
		/* do nothing since we can still function without it*/
	}
	if (unlikely(ycache_objnode_cache_create())) {
		pr_err("ycache_objnode_cache creation failed\n");
		goto error;
	}
	if (unlikely(ycache_obj_cache_create())) {
		pr_err("ycache_obj_cache creation failed\n");
		goto obj_fail;
	}
	if (unlikely(ycache_entry_cache_create())) {
		pr_err("ycache_entry_cache creation failed\n");
		goto entry_cache_fail;
	}

#ifdef CONFIG_CLEANCACHE
	ycache_cleancache_register_ops();
	pr_info("cleancache enabled using kernel transcendent memory\n");
#endif
	if (ycache_debugfs_init())
		pr_warn("debugfs initialization failed\n");

	pr_info("loaded without errors \n");
	return 0;

entry_cache_fail:
	ycache_obj_cache_destroy();
obj_fail:
	ycache_objnode_cache_destroy();
error:
	return -ENOMEM;
}

/* must be late so crypto has time to come up */
late_initcall(ycache_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Eric Zhang <gd.yi@139.com>");
MODULE_DESCRIPTION("Deduplicate pages evicted from page cache");
