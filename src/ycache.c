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
#include <linux/list.h>
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
#include <linux/shrinker.h>
#endif

#define YCACHE_GFP_MASK                                                        \
	(__GFP_FS | __GFP_NORETRY | __GFP_NOWARN | __GFP_NOMEMALLOC)
#define MAX_POOLS 256
#define MAX_PAGE_RBTREES MAX_POOLS
#define MAX_ENTRY_LISTS MAX_POOLS
#define PAGE_NR_THRESHOLD 10
/* Use MD5 as hash function for now */
#define YCACHE_HASH_FUNC "md5"
#define HASH_DIGEST_SIZE MD5_DIGEST_SIZE

/* Some of the statistics below are not protected from concurrent access for
 * performance reasons so they may not be a 100% accurate.  However,
 * they do provide useful information on roughly how many times a
 * certain event is occurring.
*/
/* Total pages used for storage */
static atomic_t ycache_used_pages = ATOMIC_INIT(0);
/* Total pages got in the module */
static atomic_t ycache_total_pages = ATOMIC_INIT(0);
/* Store failed because the ycache_entry could not be allocated */
static u64 ycache_yentry_fail;
/* Store failed because the page_entry could not be allocated */
static u64 ycache_pentry_fail;
/* Get hash value of page failed */
static u64 ycache_hash_fail;
/* Hash collision times*/
static u64 ycache_hash_collision;
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
static atomic_t ycache_curr_obj_count = ATOMIC_INIT(0);
static u64 ycache_curr_obj_count_max;
static atomic_t ycache_curr_objnode_count = ATOMIC_INIT(0);
static u64 ycache_curr_objnode_count_max;

#ifdef CONFIG_CLEANCACHE
/*********************************
* data structures
**********************************/
/* rbtree roots of page_entry, these rbtrees are all protected by
 * the lock in ycache_host
 */
static struct rb_root rbroots[MAX_PAGE_RBTREES];

/* use the hash[0] select a rbroot */
static inline struct rb_root *get_rbroot(u8 *hash) { return &rbroots[hash[0]]; }
/*
 * struct page_entry
 *
 * page   - pointer to a page, this is where data is actually stored
 * rbnode - red-black tree node
 * hash   - contains the hash value. Since we use array to store it, we
 * 	    need to hardcode the size.
 * page_nr - the  number of the same pages. When a page_entry
 * 	      is created, page_nr is 1. When the page is deduplicated,
 * 	      page_nr increase by 1. When one page is flushed, page_nr decrease
 * 	      by 1. Upon page_nr drop to 0, this page_entry should be freed.
 * 	      Changing the value required ycache_host lock being held.
 */
struct page_entry {
	struct page *page;
	struct rb_node rbnode;
	u8 hash[HASH_DIGEST_SIZE];
	int page_nr;
};

/*********************************
* page_entry functions
**********************************/
static struct kmem_cache *page_entry_cache;

static int __init page_entry_cache_create(void)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	page_entry_cache = KMEM_CACHE(page_entry, 0);
	return page_entry_cache == NULL;
}

static void __init page_entry_cache_destroy(void)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	kmem_cache_destroy(page_entry_cache);
}

/* forward reference */
static void page_entry_cache_free(struct page_entry *);

static struct page_entry *page_entry_cache_alloc(gfp_t gfp)
{
	struct page_entry *entry;

	// pr_debug("call %s()\n", __FUNCTION__);
	entry = kmem_cache_alloc(page_entry_cache, gfp);
	if (likely(entry != NULL)) {
		/* alloc page*/
		entry->page = alloc_page(gfp | __GFP_HIGHMEM);
		if (likely(entry->page != NULL)) {
			entry->page_nr = 1;
			RB_CLEAR_NODE(&entry->rbnode);
			atomic_inc(&ycache_used_pages);
			return entry;
		} else {
			page_entry_cache_free(entry);
			ycache_pentry_fail++;
			ycache_failed_get_free_pages++;
			return NULL;
		}
	} else {
		ycache_pentry_fail++;
		return NULL;
	}
}

static void page_entry_cache_free(struct page_entry *entry)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	BUG_ON(entry == NULL);
	if (likely(entry->page != NULL)) {
		__free_page(entry->page);
		atomic_dec(&ycache_used_pages);
	}
	kmem_cache_free(page_entry_cache, entry);
}

/*********************************
* page_entry rbtree functions
**********************************/
static struct page_entry *page_rb_search(struct rb_root *root, u8 *hash)
{
	struct rb_node *node = root->rb_node;
	struct page_entry *entry;
	int result;

	// pr_debug("call %s()\n", __FUNCTION__);
	while (node) {
		entry = rb_entry(node, struct page_entry, rbnode);
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
static int page_rb_insert(struct rb_root *root, struct page_entry *entry,
			  struct page_entry **dupentry)
{
	struct rb_node **link = &root->rb_node, *parent = NULL;
	struct page_entry *tmp_entry;
	int result;

	// pr_debug("call %s()\n", __FUNCTION__);
	while (*link) {
		parent = *link;
		tmp_entry = rb_entry(parent, struct page_entry, rbnode);
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

static void page_rb_erase(struct rb_root *root, struct page_entry *entry)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	if (likely(!RB_EMPTY_NODE(&entry->rbnode))) {
		rb_erase(&entry->rbnode, root);
		RB_CLEAR_NODE(&entry->rbnode);
	}
}

/* caller must hold the tree lock */
static inline void page_entry_nr_inc(struct page_entry *entry)
{
	entry->page_nr++;
}

/* caller must hold the tree lock
 * remove from the tree and free it, if nobody reference the entry
 */
static void page_entry_nr_dec(struct rb_root *rbroot, struct page_entry *entry)
{
	int page_nr = --entry->page_nr;

	BUG_ON(page_nr < 0);
	if (page_nr == 0) {
		page_rb_erase(rbroot, entry);
		page_entry_cache_free(entry);
	}
}

/*
 * page_to_hash - caculate message digest for a page
 *
 * @src:    The start virtual address of the message
 * @result: Somewhere used to store the hash value, size is HASH_DIGEST_SIZE
 *
 * Return:  0 if the caculation is successful, <0 if an error was
 * 			occurred
 *
 */
static int page_to_hash(const void *src, u8 *result)
{
	struct hash_desc desc;
	struct scatterlist sg;
	int ret = 0;

	// pr_debug("call %s()\n", __FUNCTION__);
	sg_init_one(&sg, (u8 *)src, PAGE_SIZE);
	desc.tfm = crypto_alloc_hash(YCACHE_HASH_FUNC, 0, CRYPTO_ALG_ASYNC);
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
		ycache_hash_fail++;
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

/* ycache entry lists, every tmem pool has such a list */
static struct list_head ycache_entry_lists[MAX_ENTRY_LISTS];

/* struct ycache_entry
 *
 * oid - object id in tmem, similar to inode
 * index - offset in a file
 * page_entry - pointer to page_entry where the page resides
 * list - list node in free lists for shrinker implementation
 */
struct ycache_entry {
	struct tmem_oid oid;
	uint32_t index;
	struct page_entry *page_entry;
	struct list_head list;
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

static void __init ycache_entry_cache_destroy(void)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	kmem_cache_destroy(ycache_entry_cache);
}

static struct ycache_entry *ycache_entry_cache_alloc(gfp_t gfp)
{
	struct ycache_entry *entry;

	// pr_debug("call %s()\n", __FUNCTION__);
	entry = kmem_cache_alloc(ycache_entry_cache, gfp);
	if (unlikely(entry == NULL)) {
		ycache_yentry_fail++;
		return NULL;
	}
	INIT_LIST_HEAD(&entry->list);
	atomic_inc(&ycache_total_pages);
	return entry;
}

static void ycache_entry_cache_free(struct ycache_entry *entry)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	BUG_ON(entry == NULL);
	atomic_dec(&ycache_total_pages);
	kmem_cache_free(ycache_entry_cache, entry);
}

/* ycache structure */
struct ycache_client {
	spinlock_t lock;
	struct idr tmem_pools;
};

static struct ycache_client ycache_host;

static __init void init_ycache_host(void)
{
	int i;
	// pr_debug("call %s()\n", __FUNCTION__);

	/* Init host spinlock */
	spin_lock_init(&ycache_host.lock);
	/* Init host idr */
	idr_init(&ycache_host.tmem_pools);
	/* Init page trees */
	for (i = 0; i < MAX_PAGE_RBTREES; i++) {
		rbroots[i] = RB_ROOT;
	}
	/* Init free lists*/
	for (i = 0; i < MAX_ENTRY_LISTS; i++) {
		INIT_LIST_HEAD(&ycache_entry_lists[i]);
	}
}

/*
 * Tmem operations assume the pool_id implies the invoking client.
 * ycache only has one client (the kernel itself).
 */
static struct tmem_pool *ycache_get_pool_by_id(uint16_t pool_id)
{
	struct tmem_pool *pool = NULL;

	// pr_debug("call %s()\n", __FUNCTION__);
	pool = idr_find(&ycache_host.tmem_pools, pool_id);
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

__attribute__((unused)) static void __init ycache_obj_cache_destroy(void)
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
    NULL,
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
	struct page_entry *page_entry;
	struct page_entry *dupentry;
	struct ycache_entry *ycache_entry;
	struct rb_root *rbroot;
	int result;
	u8 hash[HASH_DIGEST_SIZE];
	u8 *src, *dst;

	pr_debug("call %s()\n", __FUNCTION__);

	BUG_ON(data == NULL);

	ycache_entry = ycache_entry_cache_alloc(YCACHE_GFP_MASK);
	if (unlikely(ycache_entry == NULL)) {
		goto reject_ycache_entry;
	}
	ycache_entry->oid = *oid;
	ycache_entry->index = index;

	page = (struct page *)data;
	/* calculating MD5 may sleep, thus have to use kmap */
	src = kmap(page);
	page_to_hash(src, hash);
	kunmap(page);

	rbroot = get_rbroot(hash);
	spin_lock(&ycache_host.lock);
	page_entry = page_rb_search(rbroot, hash);
	/* hash not exists */
	if (likely(page_entry == NULL)) {
		spin_unlock(&ycache_host.lock);

		page_entry = page_entry_cache_alloc(YCACHE_GFP_MASK);
		if (unlikely(page_entry == NULL)) {
			goto reject_page_entry;
		}
		/* copy page */
		src = kmap_atomic(page);
		dst = kmap_atomic(page_entry->page);
		copy_page(dst, src);
		kunmap_atomic(dst);
		kunmap_atomic(src);
		/* copy hash values */
		memcpy(page_entry->hash, hash, HASH_DIGEST_SIZE);

		/* set page_entry before holding lock */
		ycache_entry->page_entry = page_entry;

		spin_lock(&ycache_host.lock);
		result = page_rb_insert(rbroot, page_entry, &dupentry);
		// this rarely happens, it has to be taken cared of (reject)
		// should it happen
		if (unlikely(result == -EEXIST)) {
			spin_unlock(&ycache_host.lock);
			page_entry_cache_free(page_entry);
			goto reject_page_entry;
		} else {
			/* add to free list */
			list_add_tail(&ycache_entry->list,
				      &ycache_entry_lists[pool->pool_id]);
			spin_unlock(&ycache_host.lock);
			pampd = (void *)ycache_entry;
		}
	}
	/* hash exists, compare bit by bit */
	else if (likely(is_page_same(page_entry->page, page))) {
		/* set page_entry */
		ycache_entry->page_entry = page_entry;
		/* deduplicated one page, page_nr++ */
		page_entry_nr_inc(page_entry);
		/* add to free list */
		list_add_tail(&ycache_entry->list,
			      &ycache_entry_lists[pool->pool_id]);
		spin_unlock(&ycache_host.lock);
		pampd = (void *)ycache_entry;
	}
	/* hash is the same but data is not */
	else {
		spin_unlock(&ycache_host.lock);
		ycache_hash_collision++;
		goto reject_page_entry;
	}

	return pampd;
reject_page_entry:
	ycache_entry_cache_free(ycache_entry);
reject_ycache_entry:
	return NULL;
}

static int ycache_pampd_get_data(char *data, size_t *bufsize, bool raw,
				 void *pampd, struct tmem_pool *pool,
				 struct tmem_oid *oid, uint32_t index)
{
	struct ycache_entry *ycache_entry;
	struct page_entry *page_entry;
	u8 *src, *dst;

	// pr_debug("call %s()\n", __FUNCTION__);
	// BUG_ON(is_ephemeral(pool));
	// BUG_ON(pampd == NULL);
	/* This function should not be called for now */
	BUG_ON(1);
	BUG_ON(data == NULL);

	ycache_entry = (struct ycache_entry *)pampd;
	if (ycache_entry) {
		page_entry = ycache_entry->page_entry;
		BUG_ON(page_entry == NULL);
		/* We don't aquire the lock here since pampd is not NULL, it's
		 * safe to assume page_entry can't disappear when being used.
		 */
		/* return a copy of page*/
		src = kmap_atomic(page_entry->page);
		dst = kmap_atomic((struct page *)data);
		copy_page(dst, src);
		kunmap_atomic(dst);
		kunmap_atomic(src);
		return 0;
	} else {
		return -EINVAL;
	}
}

static int ycache_pampd_get_data_and_free(char *data, size_t *bufsize, bool raw,
					  void *pampd, struct tmem_pool *pool,
					  struct tmem_oid *oid, uint32_t index)
{
	struct ycache_entry *ycache_entry;
	struct page_entry *page_entry;
	struct rb_root *rbroot;
	u8 *src, *dst;

	// pr_debug("call %s()\n", __FUNCTION__);
	BUG_ON(!is_ephemeral(pool));
	BUG_ON(pampd == NULL);
	BUG_ON(data == NULL);

	ycache_entry = (struct ycache_entry *)pampd;
	page_entry = ycache_entry->page_entry;
	BUG_ON(page_entry == NULL);

	/* Remove from list and free it */
	spin_lock(&ycache_host.lock);
	list_del(&ycache_entry->list);
	spin_unlock(&ycache_host.lock);
	ycache_entry_cache_free(ycache_entry);

	/* We don't aquire the lock here since pampd is not NULL, it's safe to
	 * assume that page_entry can't disappear when being used.
	 */
	/* Get a copy of page */
	src = kmap_atomic(page_entry->page);
	dst = kmap_atomic((struct page *)data);
	copy_page(dst, src);
	kunmap_atomic(dst);
	kunmap_atomic(src);

	rbroot = get_rbroot(page_entry->hash);
	spin_lock(&ycache_host.lock);
	/* drop one page count */
	page_entry_nr_dec(rbroot, page_entry);
	spin_unlock(&ycache_host.lock);

	return 0;
}

/*
 * free the pampd and remove it from any ycache free lists
 * pampd must no longer be pointed to from any tmem data structures!
 */
static void ycache_pampd_free(void *pampd, struct tmem_pool *pool,
			      struct tmem_oid *oid, uint32_t index)
{
	struct ycache_entry *ycache_entry;
	struct page_entry *page_entry;
	struct rb_root *rbroot;

	pr_debug("call %s()\n", __FUNCTION__);
	BUG_ON(!is_ephemeral(pool));
	BUG_ON(pampd == NULL);

	ycache_entry = (struct ycache_entry *)pampd;
	page_entry = ycache_entry->page_entry;
	BUG_ON(page_entry == NULL);

	/* Remove from list and free it */
	spin_lock(&ycache_host.lock);
	list_del(&ycache_entry->list);
	spin_unlock(&ycache_host.lock);
	ycache_entry_cache_free(ycache_entry);

	rbroot = get_rbroot(page_entry->hash);
	spin_lock(&ycache_host.lock);
	/* drop one page count */
	page_entry_nr_dec(rbroot, page_entry);
	spin_unlock(&ycache_host.lock);
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
static bool freeing = false;
static void ycache_cleancache_put_page(int pool_id,
				       struct cleancache_filekey key,
				       pgoff_t index, struct page *page)
{
	struct tmem_pool *pool;
	struct tmem_oid *oid = (struct tmem_oid *)&key;
	u32 tmp_index = (u32)index;
	int ret = -1;

	pr_debug("call %s()\n", __FUNCTION__);

	// Shrinker is being called, reject all puts
	if (unlikely(freeing == true)) {
		return;
	}

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

	pr_debug("call %s()\n", __FUNCTION__);
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

	pr_debug("call %s()\n", __FUNCTION__);
	if (unlikely(pool_id < 0))
		return;

	pool = idr_find(&ycache_host.tmem_pools, pool_id);
	if (pool == NULL)
		return;
	idr_remove(&ycache_host.tmem_pools, pool_id);
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

	pr_debug("call %s()\n", __FUNCTION__);
	BUG_ON(sizeof(struct cleancache_filekey) != sizeof(u64[3]));
	BUG_ON(pagesize != PAGE_SIZE);

	pool = kmalloc(sizeof(struct tmem_pool), GFP_KERNEL);
	if (unlikely(pool == NULL)) {
		pr_warn("pool creation failed: out of memory\n");
		goto out;
	}

	pool_id =
	    idr_alloc(&ycache_host.tmem_pools, pool, 0, MAX_POOLS, GFP_KERNEL);

	if (unlikely(pool_id < 0)) {
		pr_warn("pool creation failed: error %d\n", pool_id);
		kfree(pool);
		goto out;
	}

	atomic_set(&pool->refcount, 0);
	pool->client = &ycache_host;
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

/* return the pages count that can be freed */
static unsigned long ycache_shrinker_count(struct shrinker *shrinker,
					   struct shrink_control *sc)
{
	pr_debug("call %s() nr:%lu\n", __FUNCTION__, sc->nr_to_scan);
	return (unsigned long)atomic_read(&ycache_used_pages);
}

/* scan and free pages */
static unsigned long ycache_shrinker_scan(struct shrinker *shrinker,
					  struct shrink_control *sc)
{
	unsigned long nr = sc->nr_to_scan;
	unsigned long init_nr = nr;
	static uint32_t last_pool_id = 0;
	uint32_t pool_id = last_pool_id;
	struct tmem_pool *pool;
	struct ycache_entry *ycache_entry;
	/* the least page number a page_entry has to have to be free
	 * we try to free page_entry with lesser page_nr first
	 */
	int least_page_nr = 1;
	int empty_pool_nr = 0;

	pr_debug("call %s() nr:%lu\n", __FUNCTION__, nr);

	/* set freeing to true to reject all puts because we don't want to
	 * undo our efforts to free memory
	 */
	freeing = true;
retry:
	while ((pool_id + 1) % MAX_POOLS != last_pool_id && nr > 0) {
		spin_lock(&ycache_host.lock);
		// Check is list is empty
		if (list_empty(&ycache_entry_lists[pool_id])) {
			spin_unlock(&ycache_host.lock);
			// this list is empty, find in next one
			pool_id++;
			empty_pool_nr++;
			continue;
		}

		// Find pool success, reset counter
		empty_pool_nr = 0;
		pool = ycache_get_pool_by_id(pool_id);
		BUG_ON(pool == NULL);
		// Iterate through the list to find the first ycache_entry
		// whose corresponding page_entry has page_nr <= least_page_nr,
		// or page_nr >= PAGE_NR_THRESHOLD, which means to free all
		// page_entrys
		list_for_each_entry(ycache_entry, &ycache_entry_lists[pool_id],
				    list)
		{
			if (ycache_entry->page_entry->page_nr <=
				least_page_nr ||
			    ycache_entry->page_entry->page_nr >=
				PAGE_NR_THRESHOLD) {
				break;
			}
		}

		// Fail to find one in this list, should try next one.
		if (ycache_entry->page_entry->page_nr > least_page_nr &&
		    ycache_entry->page_entry->page_nr < PAGE_NR_THRESHOLD) {
			spin_unlock(&ycache_host.lock);
			pool_id++;
			continue;
		}

		// actually freed one page
		if (ycache_entry->page_entry->page_nr == 1)
			nr--;
		spin_unlock(&ycache_host.lock);
		tmem_flush_page(pool, &ycache_entry->oid, ycache_entry->index);
		ycache_put_pool(pool);

		// Try to spread page freeing across all pools
		last_pool_id = pool_id++;
	}
	// exit the while loop because freeing is done or all pools are empty
	if (nr == 0 || empty_pool_nr == MAX_POOLS) {
		freeing = false;
		pr_debug("end %s() init-nr:%lu\n", __FUNCTION__, init_nr - nr);
		return init_nr - nr;
	}

	// exit the while loop because can't find enough page_entry with the
	// least page_nr, needs to increase least_page_nr.
	least_page_nr++;
	goto retry;
}

static struct shrinker ycache_shrinker = {
    .count_objects = ycache_shrinker_count,
    .scan_objects = ycache_shrinker_scan,
    .seeks = DEFAULT_SEEKS,
};

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

#endif

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
	debugfs_create_u64("ycache_entry_fail", S_IRUGO, ycache_debugfs_root,
			   &ycache_yentry_fail);
	debugfs_create_u64("page_entry_fail", S_IRUGO, ycache_debugfs_root,
			   &ycache_pentry_fail);
	debugfs_create_u64("hash_fail", S_IRUGO, ycache_debugfs_root,
			   &ycache_hash_fail);
	debugfs_create_u64("hash_collision", S_IRUGO, ycache_debugfs_root,
			   &ycache_hash_collision);
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
#endif

/*
 * ycache initialization
 */

static int __init ycache_init(void)
{
	pr_info("loading\n");
#ifdef CONFIG_CLEANCACHE
	init_ycache_host();
	if (unlikely(register_cpu_notifier(&ycache_cpu_notifier_block))) {
		pr_err("can't register cpu notifier\n");
		/* do nothing since we can still function without it*/
	}
	if (unlikely(ycache_entry_cache_create())) {
		pr_err("ycache_entry_cache creation failed\n");
		goto ycache_entry_cache_fail;
	}
	if (unlikely(page_entry_cache_create())) {
		pr_err("page_entry_cache creation failed\n");
		goto entry_cache_fail;
	}
	if (unlikely(ycache_objnode_cache_create())) {
		pr_err("ycache_objnode_cache creation failed\n");
		goto ycache_objnode_cache_fail;
	}
	if (unlikely(ycache_obj_cache_create())) {
		pr_err("ycache_obj_cache creation failed\n");
		goto ycache_obj_cache_fail;
	}
	tmem_register_hostops(&ycache_hostops);
	tmem_register_pamops(&ycache_pamops);
	ycache_cleancache_register_ops();
	register_shrinker(&ycache_shrinker);
	pr_info("cleancache enabled using kernel transcendent memory\n");
#endif
#ifdef CONFIG_DEBUG_FS
	if (ycache_debugfs_init())
		pr_warn("debugfs initialization failed\n");
#endif

	pr_info("loaded without errors \n");
	return 0;

#ifdef CONFIG_CLEANCACHE
ycache_obj_cache_fail:
	ycache_objnode_cache_destroy();
ycache_objnode_cache_fail:
	page_entry_cache_destroy();
entry_cache_fail:
	ycache_entry_cache_destroy();
ycache_entry_cache_fail:
	return -ENOMEM;
#endif
}

/* must be late so crypto has time to come up */
late_initcall(ycache_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Eric Zhang <gd.yi@139.com>");
MODULE_DESCRIPTION("Deduplicate pages evicted from page cache");
