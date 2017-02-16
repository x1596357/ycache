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
#include <linux/kthread.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/highmem.h>
#include <linux/swap.h>
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
#include <linux/semaphore.h>
#include "tmem.h"

#ifdef CONFIG_CLEANCACHE
#include <linux/cleancache.h>
#include <linux/shrinker.h>
#else
#error "This module is useless without cleancache"
#endif

#define MAX_PAGE_RBTREES 256
/* Use MD5 as hash function for now */
#define YCACHE_HASH_FUNC "md5"
#define HASH_DIGEST_SIZE MD5_DIGEST_SIZE

/* Some of the statistics below are not protected from concurrent access
 * for performance reasons so they may not be a 100% accurate.  However,
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
static u64 ycache_put_to_flush;
/* Useful stats not collected by cleancache */
static u64 ycache_flush_page_found;
static u64 ycache_flush_obj_found;
static u64 ycache_failed_puts;
/* tmem statistics */
static atomic_t ycache_obj_count = ATOMIC_INIT(0);
static atomic_t ycache_objnode_count = ATOMIC_INIT(0);
static u64 ycache_objnode_fail;
static u64 ycache_obj_fail;

static int const THREADS_COUNT = 3;

/* represent a put */
struct ycache_work {
	int pool_id;
	uint32_t index;
	struct cleancache_filekey key;
	struct page *page;
	struct list_head node;
	u8 hash[HASH_DIGEST_SIZE];
};

static struct kmem_cache *work_cache;

static int __init work_cache_create(void)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	work_cache = KMEM_CACHE(ycache_work, 0);
	return work_cache == NULL;
}

static void __init work_cache_destroy(void)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	kmem_cache_destroy(work_cache);
}

/* forward reference */
static void work_cache_free(struct ycache_work *);

static struct ycache_work *work_cache_alloc(void)
{
	struct ycache_work *work;

	// pr_debug("call %s()\n", __FUNCTION__);
	work = kmem_cache_alloc(work_cache, GFP_ATOMIC);
	if (likely(work != NULL)) {
		/* copy page pointer */
		work->page = alloc_page(GFP_ATOMIC | __GFP_HIGHMEM);
		if (likely(work->page != NULL)) {
			atomic_inc(&ycache_used_pages);
			return work;
		} else {
			work_cache_free(work);
			ycache_failed_get_free_pages++;
			return NULL;
		}
	} else {
		return NULL;
	}
}

static void work_cache_free(struct ycache_work *work)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	BUG_ON(work == NULL);
	if (unlikely(work->page != NULL)) {
		__free_page(work->page);
		atomic_dec(&ycache_used_pages);
	}
	kmem_cache_free(work_cache, work);
}

/* each thread has a queue, and an extra queue to store free works */
struct ycache_workqueue {
	spinlock_t lock;
	struct list_head list;
};

/* array of ycache workqueue */
static struct ycache_workqueue *ycache_workqueues;
/* task_struct for threads */
static struct task_struct **threads;

/*********************************
* helpers
**********************************/
static atomic_t shrinking_count = ATOMIC_INIT(0);
static bool ycache_is_shrinking(void)
{
	return atomic_read(&shrinking_count) != 0;
}

/*********************************
* data structures
**********************************/
/* rbtree roots of page_entry, these rbtrees are all protected by
 * the lock in ycache_host
 */
static struct rb_root rbroots[MAX_PAGE_RBTREES];
static spinlock_t rblocks[MAX_PAGE_RBTREES];

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
} __attribute__((packed));

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

static struct page_entry *page_entry_cache_alloc(gfp_t gfp, struct page *page)
{
	struct page_entry *entry;

	// pr_debug("call %s()\n", __FUNCTION__);
	entry = kmem_cache_alloc(page_entry_cache, gfp);
	if (likely(entry != NULL)) {
		/* copy page pointer */
		entry->page = page;
		if (likely(entry->page != NULL)) {
			entry->page_nr = 1;
			RB_CLEAR_NODE(&entry->rbnode);
			// atomic_inc(&ycache_used_pages);
			return entry;
		} else {
			page_entry_cache_free(entry);
			ycache_failed_get_free_pages++;
			ycache_pentry_fail++;
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
		entry->page = NULL;
		atomic_dec(&ycache_used_pages);
	}
	kmem_cache_free(page_entry_cache, entry);
}

/*********************************
* page_entry rbtree functions
**********************************/
static struct page_entry *page_rb_search_cached(struct rb_root *root, u8 *hash,
						struct rb_node **out_parent,
						struct rb_node ***out_link)
{
	struct rb_node **link = &root->rb_node, *parent = NULL;
	struct page_entry *tmp_entry;
	int result;

	// pr_debug("call %s()\n", __FUNCTION__);
	while (*link) {
		parent = *link;
		tmp_entry = rb_entry(parent, struct page_entry, rbnode);
		result = memcmp(tmp_entry->hash, hash, HASH_DIGEST_SIZE);
		if (result > 0)
			link = &(*link)->rb_left;
		else if (result < 0)
			link = &(*link)->rb_right;
		else {
			/* found entry, parent and link should not be used */
			return tmp_entry;
		}
	}

	/* cache parent and link for later insertion */
	*out_parent = parent;
	*out_link = link;
	return NULL;
}

static int page_rb_insert_cached(struct rb_root *root, struct page_entry *entry,
				 struct rb_node *parent, struct rb_node **link)
{
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
 * Return:  0 if the caculation is successful, <0 if an error occurred
 */
static struct hash_desc *descs;
static int page_to_hash(const void *src, u8 *result, int thread_id)
{

	struct scatterlist sg;
	int ret = 0;

	// pr_debug("call %s()\n", __FUNCTION__);
	sg_init_one(&sg, (const u8 *)src, PAGE_SIZE);

	descs[thread_id].flags = 0;
	ret = crypto_hash_init(&descs[thread_id]);
	if (unlikely(ret))
		goto out;
	ret = crypto_hash_update(&descs[thread_id], &sg, PAGE_SIZE);
	if (unlikely(ret))
		goto out;
	ret = crypto_hash_final(&descs[thread_id], result);
	if (unlikely(ret))
		goto out;
out:
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

/* ycache entry lists, every tmem pool has a such list */
static struct list_head ycache_entry_list;
static spinlock_t free_list_lock;

/* struct ycache_entry
 * pool_id - tmem pool id
 * oid - object id in tmem, similar to inode
 * index - offset in a file
 * page_entry - pointer to page_entry where the page resides
 * list - list node in free lists for shrinker implementation
 */
struct ycache_entry {
	uint16_t pool_id;
	struct tmem_oid oid;
	uint32_t index;
	struct page_entry *page_entry;
	struct list_head list;
} __attribute__((packed));

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
	// INIT_LIST_HEAD(&entry->list);
	atomic_inc(&ycache_total_pages);
	return entry;
}

static void ycache_entry_cache_free(struct ycache_entry *entry)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	BUG_ON(entry == NULL);
	kmem_cache_free(ycache_entry_cache, entry);
	atomic_dec(&ycache_total_pages);
}

/* ycache structure */
struct ycache_client {
	struct idr tmem_pools;
};

static struct ycache_client ycache_host;

/*
 * Tmem operations assume the pool_id implies the invoking client.
 * ycache only has one client (the kernel itself).
 */
static struct tmem_pool *ycache_get_pool_by_id(uint16_t pool_id)
{
	struct tmem_pool *pool = NULL;

	// pr_debug("call %s()\n", __FUNCTION__);
	pool = idr_find(&ycache_host.tmem_pools, pool_id);
	if (likely(pool != NULL))
		atomic_inc(&pool->refcount);
	return pool;
}

static void ycache_put_pool(struct tmem_pool *pool)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	BUG_ON(pool == NULL);
	atomic_dec(&pool->refcount);
}

/* Tmem host ops for allocating objs and objnodes */

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

static struct tmem_obj *ycache_obj_cache_alloc(struct tmem_pool *pool)
{
	struct tmem_obj *obj = NULL;

	// pr_debug("call %s()\n", __FUNCTION__);
	/*pr_debug("%s in_atomic():%d irqs_disabled():%d\n", __FUNCTION__,
		 in_atomic(), irqs_disabled());*/
	obj = kmem_cache_alloc(ycache_obj_cache, GFP_ATOMIC);
	if (unlikely(obj == NULL)) {
		ycache_obj_fail++;
		return NULL;
	} else {
		atomic_inc(&ycache_obj_count);
		return obj;
	}
}

static void ycache_obj_cache_free(struct tmem_obj *obj, struct tmem_pool *pool)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	atomic_dec(&ycache_obj_count);
	kmem_cache_free(ycache_obj_cache, obj);
}

static struct kmem_cache *ycache_objnode_cache;
static int __init ycache_objnode_cache_create(void)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	ycache_objnode_cache = KMEM_CACHE(tmem_objnode, 0);
	return ycache_objnode_cache == NULL;
}

__attribute__((unused)) static void __init ycache_objnode_cache_destroy(void)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	kmem_cache_destroy(ycache_objnode_cache);
}

static struct tmem_objnode *ycache_objnode_cache_alloc(struct tmem_pool *pool)
{
	struct tmem_objnode *objnode = NULL;

	// pr_debug("call %s()\n", __FUNCTION__);
	/*pr_debug("%s in_atomic():%d irqs_disabled():%d\n", __FUNCTION__,
		 in_atomic(), irqs_disabled());*/
	objnode = kmem_cache_alloc(ycache_objnode_cache, GFP_ATOMIC);
	if (unlikely(objnode == NULL)) {
		ycache_objnode_fail++;
		return NULL;
	} else {
		atomic_inc(&ycache_objnode_count);
		return objnode;
	}
}

static void ycache_objnode_cache_free(struct tmem_objnode *objnode,
				      struct tmem_pool *pool)
{
	// pr_debug("call %s()\n", __FUNCTION__);
	atomic_dec(&ycache_objnode_count);
	kmem_cache_free(ycache_objnode_cache, objnode);
}

static struct tmem_hostops ycache_hostops = {
    .obj_alloc = ycache_obj_cache_alloc,
    .obj_free = ycache_obj_cache_free,
    .objnode_alloc = ycache_objnode_cache_alloc,
    .objnode_free = ycache_objnode_cache_free,
};

/* use tmem to manage the relation of page address and ycache_entry.
 * pampd is (void *)(struct ycache_entry *)
 */

static void *ycache_pampd_create(char *data, size_t size, bool raw, int eph,
				 struct tmem_pool *pool, struct tmem_oid *oid,
				 uint32_t index)
{
	void *pampd = NULL;
	struct ycache_entry *ycache_entry;
	struct rb_root *rbroot;
	struct page_entry *page_entry;
	struct rb_node *parent = NULL;
	struct rb_node **link = NULL;
	struct ycache_work *this_work;

	// pr_debug("call %s()\n", __FUNCTION__);
	/*pr_debug("%s in_atomic():%d irqs_disabled():%d\n", __FUNCTION__,
		 in_atomic(), irqs_disabled());*/

	BUG_ON(data == NULL);

	ycache_entry = ycache_entry_cache_alloc(GFP_ATOMIC);
	if (unlikely(ycache_entry == NULL)) {
		goto reject_ycache_entry;
	}
	ycache_entry->pool_id = pool->pool_id;
	ycache_entry->oid = *oid;
	ycache_entry->index = index;

	this_work = (struct ycache_work *)data;

	rbroot = get_rbroot(this_work->hash);
	spin_lock(&rblocks[this_work->hash[0]]);
	page_entry =
	    page_rb_search_cached(rbroot, this_work->hash, &parent, &link);
	if (page_entry != NULL)
		page_entry_nr_inc(page_entry);
	/* hash not exists */
	if (page_entry == NULL) {
		page_entry =
		    page_entry_cache_alloc(GFP_ATOMIC, this_work->page);
		if (unlikely(page_entry == NULL)) {
			spin_unlock(&rblocks[this_work->hash[0]]);
			goto reject_page_entry;
		}
		/* copy hash values */
		memcpy(page_entry->hash, this_work->hash, HASH_DIGEST_SIZE);
		/*
		* insert page entry to rb-tree
		* use parent and link cached from page_rb_search_cached()
		* if page_entry is not NULL, parent and link should not be used
		*/
		page_rb_insert_cached(rbroot, page_entry, parent, link);
		spin_unlock(&rblocks[this_work->hash[0]]);
		/* this page is used to store unique page, set it to
		NULL so it won't be freed in ycache_thread */
		this_work->page = NULL;
		/* copy page_entry pointer for later reference */
		ycache_entry->page_entry = page_entry;
		/* add to free list */
		spin_lock(&free_list_lock);
		list_add_tail(&ycache_entry->list, &ycache_entry_list);
		spin_unlock(&free_list_lock);
		pampd = (void *)ycache_entry;
	}
	/* hash exists, compare bit by bit */
	else if (likely(is_page_same(page_entry->page, this_work->page))) {
		spin_unlock(&rblocks[this_work->hash[0]]);
		/* set page_entry */
		ycache_entry->page_entry = page_entry;
		/* add to free list */
		spin_lock(&free_list_lock);
		list_add_tail(&ycache_entry->list, &ycache_entry_list);
		spin_unlock(&free_list_lock);
		pampd = (void *)ycache_entry;
	}
	/* hash is the same but data is not */
	else {
		page_entry_nr_dec(rbroot, page_entry);
		spin_unlock(&rblocks[this_work->hash[0]]);
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
	BUG_ON(is_ephemeral(pool));
	BUG_ON(pampd == NULL);

	/* This function should not be called for now */
	BUG();
	BUG_ON(data == NULL);

	ycache_entry = (struct ycache_entry *)pampd;
	if (likely(ycache_entry != NULL)) {
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
	}

	return -EINVAL;
}

static int ycache_pampd_get_data_and_free(char *data, size_t *bufsize, bool raw,
					  void *pampd, struct tmem_pool *pool,
					  struct tmem_oid *oid, uint32_t index)
{
	struct ycache_entry *ycache_entry;
	struct page_entry *page_entry;
	struct rb_root *rbroot;
	u8 *src, *dst;
	unsigned int hash0;

	// pr_debug("call %s()\n", __FUNCTION__);
	BUG_ON(!is_ephemeral(pool));
	BUG_ON(pampd == NULL);
	BUG_ON(data == NULL);

	ycache_entry = (struct ycache_entry *)pampd;
	page_entry = ycache_entry->page_entry;
	BUG_ON(page_entry == NULL);

	/* Remove from list and free it */
	spin_lock(&free_list_lock);
	list_del_init(&ycache_entry->list);
	spin_unlock(&free_list_lock);
	ycache_entry_cache_free(ycache_entry);

	/* We don't aquire the lock here since pampd is not NULL, it's safe to
	 assume that page_entry can't disappear when being used */
	/* Get a copy of page */
	src = kmap_atomic(page_entry->page);
	dst = kmap_atomic((struct page *)data);
	copy_page(dst, src);
	kunmap_atomic(dst);
	kunmap_atomic(src);

	rbroot = get_rbroot(page_entry->hash);
	hash0 = page_entry->hash[0];
	spin_lock(&rblocks[hash0]);
	/* drop one page count */
	page_entry_nr_dec(rbroot, page_entry);
	spin_unlock(&rblocks[hash0]);

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
	unsigned int hash0;

	// pr_debug("call %s()\n", __FUNCTION__);
	BUG_ON(pampd == NULL);

	ycache_entry = (struct ycache_entry *)pampd;
	page_entry = ycache_entry->page_entry;
	BUG_ON(page_entry == NULL);

	/* Remove from list and free it */
	spin_lock(&free_list_lock);
	list_del_init(&ycache_entry->list);
	spin_unlock(&free_list_lock);
	ycache_entry_cache_free(ycache_entry);

	rbroot = get_rbroot(page_entry->hash);
	hash0 = page_entry->hash[0];
	spin_lock(&rblocks[hash0]);
	/* drop one page count */
	page_entry_nr_dec(rbroot, page_entry);
	spin_unlock(&rblocks[hash0]);
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
 * pagecache pages;
 */

static void ycache_cleancache_put_page(int pool_id,
				       struct cleancache_filekey key,
				       pgoff_t index, struct page *page)
{
	u8 *src, *dst;
	int thread_id;
	struct ycache_work *this_work;
	uint32_t tmp_index;

	// pr_debug("call %s()\n", __FUNCTION__);
	/*pr_debug("%s in_atomic():%d irqs_disabled():%d\n", __FUNCTION__,
		 in_atomic(), irqs_disabled());*/
	tmp_index = (uint32_t)index;
	if (unlikely(tmp_index != index)) {
		ycache_failed_puts++;
		return;
	}

	// Shrinker is being called, reject all puts
	if (unlikely(ycache_is_shrinking())) {
		ycache_failed_puts++;
		return;
	}

	this_work = work_cache_alloc();
	if (this_work == NULL) {
		// pr_debug("%s return\n", __FUNCTION__);
		return;
	} else {
		this_work->pool_id = pool_id;
		this_work->key = key;
		this_work->index = tmp_index;

		/* copy page */
		src = kmap_atomic(page);
		dst = kmap_atomic(this_work->page);
		copy_page(dst, src);
		kunmap_atomic(dst);
		kunmap_atomic(src);

		thread_id = this_work->index % THREADS_COUNT;
		// pr_info("allocate put to thread/%d", thread_id);
		spin_lock(&ycache_workqueues[thread_id].lock);
		list_add_tail(&this_work->node,
			      &ycache_workqueues[thread_id].list);
		spin_unlock(&ycache_workqueues[thread_id].lock);
		wake_up_process(threads[thread_id]);
	}
}

static void ycache_cleancache_do_put_page(struct ycache_work *work)
{
	struct tmem_pool *pool;
	struct tmem_oid *oid = (struct tmem_oid *)&work->key;
	uint32_t index = work->index;
	int ret = -1;
	unsigned long flags;

	// pr_debug("call %s()\n", __FUNCTION__);
	/*pr_debug("%s in_atomic():%d irqs_disabled():%d\n", __FUNCTION__,
		 in_atomic(), irqs_disabled());*/
	local_irq_save(flags);
	pool = ycache_get_pool_by_id(work->pool_id);
	if (likely(pool != NULL)) {
		ret = tmem_put(pool, oid, index, (char *)(work), PAGE_SIZE, 0,
			       is_ephemeral(pool));
		if (unlikely(ret < 0)) {
			ycache_failed_puts++;
			ycache_put_pool(pool);
			goto fail;
		}
		ycache_put_pool(pool);
	}
	local_irq_restore(flags);
	return;
fail:
	/* flush if put failed */
	local_irq_save(flags);
	pool = ycache_get_pool_by_id(work->pool_id);
	if (likely(pool != NULL && atomic_read(&pool->obj_count) > 0)) {
		(void)tmem_flush_page(pool, oid, index);
	}
	ycache_put_pool(pool);
	local_irq_restore(flags);
	ycache_put_to_flush++;
}

static int ycache_cleancache_get_page(int pool_id,
				      struct cleancache_filekey key,
				      pgoff_t index, struct page *page)
{
	struct tmem_pool *pool;
	struct tmem_oid *oid = (struct tmem_oid *)&key;
	uint32_t tmp_index = (uint32_t)index;
	size_t size = PAGE_SIZE;
	int ret = -1;
	unsigned long flags;

	// pr_debug("call %s()\n", __FUNCTION__);
	if (unlikely(tmp_index != index))
		goto out;

	local_irq_save(flags);
	pool = ycache_get_pool_by_id(pool_id);
	if (likely(pool != NULL)) {
		if (likely(atomic_read(&pool->obj_count) > 0))
			ret = tmem_get(pool, oid, tmp_index, (char *)(page),
				       &size, 0, is_ephemeral(pool));
		ycache_put_pool(pool);
	}
	local_irq_restore(flags);
out:
	return ret;
}

static void ycache_cleancache_flush_page(int pool_id,
					 struct cleancache_filekey key,
					 pgoff_t index)
{
	struct tmem_pool *pool;
	struct tmem_oid *oid = (struct tmem_oid *)&key;
	uint32_t tmp_index = (uint32_t)index;
	struct ycache_work *work;
	struct ycache_work *tmp_work;
	int thread_id;
	int ret = -1;
	unsigned long flags;

	// pr_debug("call %s()\n", __FUNCTION__);
	if (unlikely(tmp_index != index))
		return;

	thread_id = index % THREADS_COUNT;

	/* check if ycache_workqueue contains such page */
	spin_lock(&ycache_workqueues[thread_id].lock);
	if (unlikely(!list_empty(&ycache_workqueues[thread_id].list))) {
		list_for_each_entry_safe(
		    work, tmp_work, &ycache_workqueues[thread_id].list, node)
		{
			if (work->index == index &&
			    tmem_oid_compare((struct tmem_oid *)(&work->key),
					     oid) == 0 &&
			    work->pool_id == pool_id) {
				list_del_init(&work->node);
				work_cache_free(work);
			}
		}
	}
	spin_unlock(&ycache_workqueues[thread_id].lock);

	local_irq_save(flags);
	pool = ycache_get_pool_by_id(pool_id);
	if (likely(pool != NULL)) {
		if (likely(atomic_read(&pool->obj_count) > 0))
			ret = tmem_flush_page(pool, oid, tmp_index);
		ycache_put_pool(pool);
	}
	local_irq_restore(flags);
	if (likely(ret >= 0))
		ycache_flush_page_found++;
}

static void ycache_cleancache_flush_inode(int pool_id,
					  struct cleancache_filekey key)
{
	struct tmem_pool *pool;
	struct tmem_oid *oid = (struct tmem_oid *)&key;
	struct ycache_work *work;
	struct ycache_work *tmp_work;
	int i;
	int ret = -1;
	unsigned long flags;

	// pr_debug("call %s()\n", __FUNCTION__);
	/* check if ycache_workqueue contains such page */
	for (i = 0; i < THREADS_COUNT; i++) {
		spin_lock(&ycache_workqueues[i].lock);
		if (unlikely(!list_empty(&ycache_workqueues[i].list))) {
			list_for_each_entry_safe(
			    work, tmp_work, &ycache_workqueues[i].list, node)
			{
				if (tmem_oid_compare(
					(struct tmem_oid *)(&work->key), oid) ==
					0 &&
				    work->pool_id == pool_id) {
					list_del_init(&work->node);
					work_cache_free(work);
				}
			}
		}
		spin_unlock(&ycache_workqueues[i].lock);
	}

	local_irq_save(flags);
	pool = ycache_get_pool_by_id(pool_id);
	if (likely(pool != NULL)) {
		if (likely(atomic_read(&pool->obj_count) > 0))
			ret = tmem_flush_object(pool, oid);
		ycache_put_pool(pool);
	}
	local_irq_restore(flags);
	if (likely(ret >= 0))
		ycache_flush_obj_found++;
}

static void ycache_cleancache_flush_fs(int pool_id)
{
	struct tmem_pool *pool = NULL;

	// pr_debug("call %s()\n", __FUNCTION__);
	if (unlikely(pool_id < 0))
		return;

	pool = idr_find(&ycache_host.tmem_pools, pool_id);
	if (unlikely(pool == NULL))
		return;
	idr_remove(&ycache_host.tmem_pools, pool_id);
	/* wait for pool activity on other cpus to quit */
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

	pool = kmalloc(sizeof(struct tmem_pool), GFP_ATOMIC);
	if (unlikely(pool == NULL)) {
		pr_warn("pool creation failed: out of memory\n");
		goto out;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
	idr_preload(GFP_ATOMIC);
	pool_id = idr_alloc(&ycache_host.tmem_pools, pool, 0, 0, GFP_ATOMIC);
	idr_preload_end();
#else
	int ret;
	do {
		ret = idr_pre_get(&ycache_host.tmem_pools, GFP_ATOMIC);
		if (unlikely(ret != 1)) {
			kfree(pool);
			pr_info("get pool_id failed: out of memory\n");
			goto out;
		}
		ret = idr_get_new(&ycache_host.tmem_pools, pool, &pool_id);
	} while (ret == -EAGAIN);
	if (unlikely(ret)) {
		pr_info("get pool_id failed: error %d\n", ret);
		kfree(pool);
		goto out;
	}
#endif

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

/* return the ycache_total_pages count as object count */
static unsigned long ycache_shrinker_count(struct shrinker *shrinker,
					   struct shrink_control *sc)
{
	// pr_debug("call %s() nr:%lu\n", __FUNCTION__,(unsigned
	// long)atomic_read(&ycache_total_pages));
	return (unsigned long)atomic_read(&ycache_total_pages);
}

/* ycache shrinker  */
static unsigned long ycache_shrink(unsigned long nr)
{
	unsigned long freed_nr = 0;
	int pool_id;
	struct tmem_pool *pool;
	struct tmem_oid oid;
	uint32_t index;
	struct ycache_entry *ycache_entry;
	int ret = -1;

// pr_debug("call %s() nr:%lu\n", __FUNCTION__, nr);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 12, 0)
	if (freed_nr == 0) {
		return atomic_read(&ycache_total_pages);
	}
#endif
	atomic_inc(&shrinking_count);
	while (freed_nr < nr) {
		spin_lock(&free_list_lock);
		ycache_entry = list_first_entry_or_null(
		    &ycache_entry_list, struct ycache_entry, list);
		if (unlikely(ycache_entry == NULL)) {
			/* list is empty */
			spin_unlock(&free_list_lock);
			break;
		} else {
			pool_id = ycache_entry->pool_id;
			oid = ycache_entry->oid;
			index = ycache_entry->index;
			spin_unlock(&free_list_lock);
		}

		pool = ycache_get_pool_by_id(pool_id);
		if (likely(pool != NULL)) {
			if (likely(atomic_read(&pool->obj_count) > 0))
				ret = tmem_flush_page(pool, &oid, index);
			ycache_put_pool(pool);
		}
		if (likely(ret >= 0)) {
			ycache_flush_page_found++;
			freed_nr++;
		}
	}

	atomic_dec(&shrinking_count);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
	return freed_nr;
#else
	return atomic_read(&ycache_total_pages);
#endif
}

/* scan and free pages */
static unsigned long ycache_shrinker_scan(struct shrinker *shrinker,
					  struct shrink_control *sc)
{
	return ycache_shrink(sc->nr_to_scan);
}

static struct shrinker ycache_shrinker = {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
    .count_objects = ycache_shrinker_count,
    .scan_objects = ycache_shrinker_scan,
#else
    .shrink = ycache_shrinker_scan,
#endif
    .seeks = DEFAULT_SEEKS,
};

/* ycache kernel threads to utilize SMP system */
static int ycache_thread(void *data)
{
	int thread_id;
	struct ycache_workqueue *this_wq;
	struct ycache_work *this_work;
	u8 *src;
	int ret;

	thread_id = (int)data;
	this_wq = &ycache_workqueues[thread_id];

	pr_info("thread_id:%d\n", thread_id);
	/*pr_debug("%s in_atomic():%d irqs_disabled():%d\n", __FUNCTION__,
		 in_atomic(), irqs_disabled());*/
	for (;;) {
		/* Code is constructed this way to avoid wake-up lost */
		set_current_state(TASK_INTERRUPTIBLE);
		spin_lock(&this_wq->lock);
		this_work = list_first_entry_or_null(&this_wq->list,
						     struct ycache_work, node);
		while (this_work == NULL) {
			spin_unlock(&this_wq->lock);
			schedule();
			set_current_state(TASK_INTERRUPTIBLE);
			spin_lock(&this_wq->lock);
			this_work = list_first_entry_or_null(
			    &this_wq->list, struct ycache_work, node);
		}
		set_current_state(TASK_RUNNING);
		list_del_init(&this_work->node);
		spin_unlock(&this_wq->lock);

		/* calculating MD5 */
		src = kmap(this_work->page);
		ret = page_to_hash(src, this_work->hash, thread_id);
		kunmap(this_work->page);

		if (ret == 0) {
			ycache_cleancache_do_put_page(this_work);
		}

		work_cache_free(this_work);
	}
	/* we don't return, return written here to avoid compiler warning */
	return 0;
}

static __init int do_ycache_init(void)
{
	//	struct ycache_work *works;
	int i;
	// pr_debug("call %s()\n", __FUNCTION__);

	/* Init host idr */
	idr_init(&ycache_host.tmem_pools);
	/* Init page trees */
	for (i = 0; i < MAX_PAGE_RBTREES; i++) {
		rbroots[i] = RB_ROOT;
		spin_lock_init(&rblocks[i]);
	}
	spin_lock_init(&free_list_lock);
	/* Init free list for ycache entry*/
	INIT_LIST_HEAD(&ycache_entry_list);

	/* Init hash_desc for page_to_hash() */
	descs = kmalloc(sizeof(struct hash_desc) * THREADS_COUNT, GFP_KERNEL);
	if (unlikely(descs == NULL)) {
		goto fail;
	} else {
		for (i = 0; i < THREADS_COUNT; i++) {
			descs[i].tfm =
			    crypto_alloc_hash(YCACHE_HASH_FUNC, 0, 0);
			/* fail to allocate a cipher handle */
			if (unlikely(IS_ERR(descs[i].tfm))) {
				goto alloc_hash_fail;
			}
		}
	}
	/* Init thread related data structure*/
	/* work queues for each thread */
	ycache_workqueues = kmalloc(
	    sizeof(struct ycache_workqueue) * THREADS_COUNT, GFP_KERNEL);
	if (unlikely(ycache_workqueues == NULL)) {
		goto ycache_workqueues_fail;
	} else {
		for (i = 0; i < THREADS_COUNT; i++) {
			spin_lock_init(&ycache_workqueues[i].lock);
			INIT_LIST_HEAD(&ycache_workqueues[i].list);
		}
	}

	/* threads */
	threads =
	    kmalloc(sizeof(struct task_struct *) * THREADS_COUNT, GFP_KERNEL);
	if (unlikely(threads == NULL)) {
		goto threads_fail;
	} else {
		for (i = 0; i < THREADS_COUNT; i++) {
			threads[i] = kthread_create(ycache_thread, (void *)i,
						    "kycached/%d", i);
			BUG_ON(IS_ERR(threads[i]));
		}
	}

	return 0;

threads_fail:
	kfree(ycache_workqueues);
ycache_workqueues_fail:
alloc_hash_fail:
	for (i = 0; i < THREADS_COUNT; i++) {
		if (!IS_ERR(descs[i].tfm)) {
			crypto_free_hash(descs[i].tfm);
		}
	}
	kfree(descs);
fail:
	return -ENOMEM;
}

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	debugfs_create_atomic_t("used_pages", S_IRUGO, ycache_debugfs_root,
				&ycache_used_pages);
	debugfs_create_atomic_t("total_pages", S_IRUGO, ycache_debugfs_root,
				&ycache_total_pages);
	debugfs_create_atomic_t("obj_count", S_IRUGO, ycache_debugfs_root,
				&ycache_obj_count);
	debugfs_create_atomic_t("objnode_count", S_IRUGO, ycache_debugfs_root,
				&ycache_objnode_count);
#else
	debugfs_create_u32("used_pages", S_IRUGO, ycache_debugfs_root,
			   (u32 *)&ycache_used_pages);
	debugfs_create_u32("total_pages", S_IRUGO, ycache_debugfs_root,
			   (u32 *)&ycache_total_pages);
	debugfs_create_u32("obj_count", S_IRUGO, ycache_debugfs_root,
			   (u32 *)&ycache_obj_count);
	debugfs_create_u32("objnode_count", S_IRUGO, ycache_debugfs_root,
			   (u32 *)&ycache_objnode_count);
#endif
	debugfs_create_u64("fail_ycache_entry", S_IRUGO, ycache_debugfs_root,
			   &ycache_yentry_fail);
	debugfs_create_u64("fail_page_entry", S_IRUGO, ycache_debugfs_root,
			   &ycache_pentry_fail);
	debugfs_create_u64("fail_hash", S_IRUGO, ycache_debugfs_root,
			   &ycache_hash_fail);
	debugfs_create_u64("hash_collision", S_IRUGO, ycache_debugfs_root,
			   &ycache_hash_collision);
	debugfs_create_u64("flush_page_found", S_IRUGO, ycache_debugfs_root,
			   &ycache_flush_page_found);
	debugfs_create_u64("flush_obj_found", S_IRUGO, ycache_debugfs_root,
			   &ycache_flush_obj_found);
	debugfs_create_u64("fail_puts", S_IRUGO, ycache_debugfs_root,
			   &ycache_failed_puts);
	debugfs_create_u64("fail_get_free_page", S_IRUGO, ycache_debugfs_root,
			   &ycache_failed_get_free_pages);
	debugfs_create_u64("put_to_flush", S_IRUGO, ycache_debugfs_root,
			   &ycache_put_to_flush);
	debugfs_create_u64("fail_get_obj", S_IRUGO, ycache_debugfs_root,
			   &ycache_obj_fail);
	debugfs_create_u64("fail_get_objnode", S_IRUGO, ycache_debugfs_root,
			   &ycache_objnode_fail);

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
	if (unlikely(do_ycache_init())) {
		pr_err("do_ycache_init failed\n");
		goto do_ycache_init_fail;
	}
	if (unlikely(work_cache_create())) {
		pr_err("work_cache creation failed\n");
		goto work_cache_fail;
	}
	if (unlikely(ycache_entry_cache_create())) {
		pr_err("ycache_entry_cache creation failed\n");
		goto ycache_entry_cache_fail;
	}
	if (unlikely(page_entry_cache_create())) {
		pr_err("page_entry_cache creation failed\n");
		goto entry_cache_fail;
	}
	if (unlikely(ycache_obj_cache_create())) {
		pr_err("ycache_obj_cache creation failed\n");
		goto ycache_obj_cache_fail;
	}
	if (unlikely(ycache_objnode_cache_create())) {
		pr_err("ycache_objnode_cache creation failed\n");
		goto ycache_objnode_cache_fail;
	}
	tmem_register_hostops(&ycache_hostops);
	tmem_register_pamops(&ycache_pamops);
	cleancache_register_ops(&ycache_cleancache_ops);
	pr_info("cleancache enabled using kernel transcendent memory\n");
	register_shrinker(&ycache_shrinker);
#endif
#ifdef CONFIG_DEBUG_FS
	if (ycache_debugfs_init())
		pr_warn("debugfs initialization failed\n");
#endif

	pr_info("loaded without errors \n");
	return 0;

#ifdef CONFIG_CLEANCACHE
ycache_objnode_cache_fail:
	ycache_obj_cache_destroy();
ycache_obj_cache_fail:
	page_entry_cache_destroy();
entry_cache_fail:
	ycache_entry_cache_destroy();
ycache_entry_cache_fail:
	work_cache_destroy();
work_cache_fail:
do_ycache_init_fail:
	return -ENOMEM;
#endif
}

/* must be late so crypto has time to come up */
late_initcall(ycache_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Eric Zhang <gd.yi@139.com>");
MODULE_DESCRIPTION("Deduplicate pages evicted from page cache and cache them");
