// SPDX-License-Identifier: GPL-2.0

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cleancache.h>
#include <linux/hashtable.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/cma.h>
#include <linux/idr.h>
#include <linux/sysfs.h>
#include "cma.h"

/*
 * page->units : area id
 * page->mapping : struct gcma_inode
 * page->index : page offset from inode
 */

#define GCMA_HASH_BITS	10

/*
 * Cleancache API(e.g., cleancache_putpage) is called under IRQ disabled
 * context. Thus, The locks taken in the cleancache API path should take
 * care of the irq locking.
 */

static DEFINE_SPINLOCK(gcma_fs_lock);
static DEFINE_IDR(gcma_fs_idr);

#define MAX_EVICT_BATCH 64UL

static LIST_HEAD(gcma_lru);
static DEFINE_SPINLOCK(lru_lock);

static atomic_t nr_gcma_area = ATOMIC_INIT(0);

static atomic64_t gcma_stored_page = ATOMIC64_INIT(0);
static atomic64_t gcma_loaded_page = ATOMIC64_INIT(0);
static atomic64_t gcma_evicted_page = ATOMIC64_INIT(0);
static atomic64_t gcma_cached_page = ATOMIC64_INIT(0);

/* represent reserved memory range */
struct gcma_area {
	struct list_head free_pages;
	spinlock_t free_pages_lock;
	unsigned long start_pfn;
	unsigned long end_pfn;
};

struct gcma_area areas[MAX_CMA_AREAS];

/* represents each file system instance hosted by the cleancache */
struct gcma_fs {
	spinlock_t hash_lock;
	DECLARE_HASHTABLE(inode_hash, GCMA_HASH_BITS);
};

/*
 * @gcma_inode represents each inode in @gcma_fs
 *
 * The gcma_inode will be freed by RCU(except invalidate_inode)
 * when the last page from xarray will be freed.
 */
struct gcma_inode {
	struct cleancache_filekey key;
	struct hlist_node hash;
	refcount_t ref_count;

	struct xarray pages;
	struct rcu_head rcu;
	struct gcma_fs *gcma_fs;
};

static struct kmem_cache *slab_gcma_inode;

static void add_page_to_lru(struct page *page)
{
	VM_BUG_ON(!irqs_disabled());
	VM_BUG_ON(!list_empty(&page->lru));

	spin_lock(&lru_lock);
	list_add(&page->lru, &gcma_lru);
	spin_unlock(&lru_lock);
}

static void rotate_lru_page(struct page *page)
{
	VM_BUG_ON(!irqs_disabled());

	spin_lock(&lru_lock);
	if (!list_empty(&page->lru))
		list_move(&page->lru, &gcma_lru);
	spin_unlock(&lru_lock);
}

static void delete_page_from_lru(struct page *page)
{
	VM_BUG_ON(!irqs_disabled());

	spin_lock(&lru_lock);
	if (!list_empty(&page->lru))
		list_del_init(&page->lru);
	spin_unlock(&lru_lock);
}

static void SetPageGCMAFree(struct page *page)
{
	SetPagePrivate(page);
}

static int PageGCMAFree(struct page *page)
{
	return PagePrivate(page);
}

static void ClearPageGCMAFree(struct page *page)
{
	ClearPagePrivate(page);
}

static struct gcma_inode *alloc_gcma_inode(struct gcma_fs *gcma_fs,
					struct cleancache_filekey *key)
{
	struct gcma_inode *inode;

	inode = kmem_cache_alloc(slab_gcma_inode, GFP_ATOMIC|__GFP_NOWARN);
	if (inode) {
		memcpy(&inode->key, key, sizeof(*key));
		xa_init_flags(&inode->pages, XA_FLAGS_LOCK_IRQ);
		INIT_HLIST_NODE(&inode->hash);
		inode->gcma_fs = gcma_fs;
		refcount_set(&inode->ref_count, 1);
	}

	return inode;
}

static void gcma_inode_free(struct rcu_head *rcu)
{
	struct gcma_inode *inode = container_of(rcu, struct gcma_inode, rcu);

	VM_BUG_ON(!xa_empty(&inode->pages));
	kmem_cache_free(slab_gcma_inode, inode);
}

static bool get_gcma_inode(struct gcma_inode *inode)
{
	return refcount_inc_not_zero(&inode->ref_count);
}

static void __put_gcma_inode(struct gcma_inode *inode)
{
	hlist_del_init_rcu(&inode->hash);

	call_rcu(&inode->rcu, gcma_inode_free);
}

static void put_gcma_inode(struct gcma_inode *inode)
{
	if (refcount_dec_and_test(&inode->ref_count)) {
		unsigned long flags;
		struct gcma_fs *gcma_fs = inode->gcma_fs;

		spin_lock_irqsave(&gcma_fs->hash_lock, flags);
		__put_gcma_inode(inode);
		spin_unlock_irqrestore(&gcma_fs->hash_lock, flags);
	}
}

static struct gcma_inode *find_and_get_gcma_inode(struct gcma_fs *gcma_fs,
						struct cleancache_filekey *key)
{
	struct gcma_inode *tmp, *inode = NULL;

	rcu_read_lock();
	hash_for_each_possible_rcu(gcma_fs->inode_hash, tmp, hash, key->u.ino) {
		if (memcmp(&tmp->key, key, sizeof(*key)))
			continue;
		if (get_gcma_inode(tmp)) {
			inode = tmp;
			break;
		}
	}
	rcu_read_unlock();

	return inode;
}

static struct gcma_inode *add_gcma_inode(struct gcma_fs *gcma_fs,
						struct cleancache_filekey *key)
{
	struct gcma_inode *inode, *tmp;

	inode = alloc_gcma_inode(gcma_fs, key);
	if (!inode)
		return ERR_PTR(-ENOMEM);

	spin_lock(&gcma_fs->hash_lock);
	tmp = find_and_get_gcma_inode(gcma_fs, key);
	if (tmp) {
		spin_unlock(&gcma_fs->hash_lock);
		/* someone already added it */
		put_gcma_inode(inode);
		put_gcma_inode(tmp);
		return ERR_PTR(-EEXIST);
	}
	hash_add_rcu(gcma_fs->inode_hash, &inode->hash, key->u.ino);
	spin_unlock(&gcma_fs->hash_lock);

	return inode;
}

void gcma_area_init(unsigned long pfn, unsigned long page_count)
{
	unsigned long i;
	struct page *page;
	struct gcma_area *area;
	int area_id;

	area_id = atomic_fetch_inc(&nr_gcma_area);
	VM_BUG_ON(area_id == MAX_CMA_AREAS);

	area = &areas[area_id];
	INIT_LIST_HEAD(&area->free_pages);
	spin_lock_init(&area->free_pages_lock);

	for (i = 0; i < page_count; i++) {
		page = pfn_to_page(pfn + i);
		/* Never changed since the id set up */
		page->units = area_id;
		page->mapping = NULL;
		page->index = 0;
		SetPageGCMAFree(page);
		list_add(&page->lru, &area->free_pages);
	}

	area->start_pfn = pfn;
	area->end_pfn = pfn + page_count - 1;

	pr_info("[%d] GCMA area initialized\n", area_id);
}

static void page_area_lock(struct page *page)
{
	struct gcma_area *area;

	VM_BUG_ON(!irqs_disabled());

	area = &areas[page->units];
	spin_lock(&area->free_pages_lock);
}

static void page_area_unlock(struct page *page)
{
	struct gcma_area *area;

	area = &areas[page->units];
	spin_unlock(&area->free_pages_lock);
}

static struct page *gcma_alloc_page(void)
{
	int i, nr_area;
	struct gcma_area *area;
	struct page *page = NULL;

	VM_BUG_ON(!irqs_disabled());

	nr_area = atomic_read(&nr_gcma_area);

	for (i = 0; i < nr_area; i++) {
		area = &areas[i];
		spin_lock(&area->free_pages_lock);
		if (list_empty(&area->free_pages)) {
			spin_unlock(&area->free_pages_lock);
			continue;
		}

		page = list_last_entry(&area->free_pages, struct page, lru);
		list_del_init(&page->lru);

		ClearPageGCMAFree(page);
		set_page_count(page, 1);
		spin_unlock(&area->free_pages_lock);
		atomic64_inc(&gcma_cached_page);
		break;
	}

	return page;
}

static void __gcma_free_page(struct page *page)
{
	struct gcma_area *area = &areas[page->units];

	page->mapping = NULL;
	page->index = 0;
	VM_BUG_ON(!list_empty(&page->lru));
	list_add(&page->lru, &area->free_pages);
	SetPageGCMAFree(page);
}

static void gcma_free_page(struct page *page)
{
	__gcma_free_page(page);
	atomic64_dec(&gcma_cached_page);
}

static inline void gcma_get_page(struct page *page)
{
	get_page(page);
}

static inline bool gcma_get_page_unless_zero(struct page *page)
{
	return get_page_unless_zero(page);
}

static void gcma_put_page(struct page *page)
{
	if (put_page_testzero(page)) {
		unsigned long flags;
		struct gcma_inode *inode = (struct gcma_inode *)page->mapping;

		local_irq_save(flags);
		delete_page_from_lru(page);
		page_area_lock(page);
		gcma_free_page(page);
		page_area_unlock(page);
		local_irq_restore(flags);
		if (inode)
			put_gcma_inode(inode);
	}
}

static int gcma_store_page(struct gcma_inode *inode, unsigned long index,
				struct page *page)
{
	int err = xa_err(__xa_store(&inode->pages, index,
				page, GFP_ATOMIC|__GFP_NOWARN));

	if (!err) {
		refcount_inc(&inode->ref_count);
		gcma_get_page(page);
		page->mapping = (struct address_space *)inode;
		page->index = index;
	}

	return err;
}

static void gcma_erase_page(struct gcma_inode *inode, unsigned long index,
				struct page *page)
{
	/* The inode refcount will decrease when the page is freed */
	__xa_erase(&inode->pages, index);
	gcma_put_page(page);
}

static void __gcma_discard_range(struct gcma_area *area,
				unsigned long start_pfn,
				unsigned long end_pfn)
{
	unsigned long pfn;
	struct page *page;
	unsigned long scanned = 0;

	local_irq_disable();

	for (pfn = start_pfn; pfn <= end_pfn; pfn++) {
		struct gcma_inode *inode;
		unsigned long index;
again:
		if (!(++scanned % XA_CHECK_SCHED)) {
			/* let in any pending interrupt */
			local_irq_enable();
			cond_resched();
			local_irq_disable();
		}

		page = pfn_to_page(pfn);
		page_area_lock(page);
		if (PageGCMAFree(page)) {
			/*
			 * Isolate page from the free list to prevent further
			 * allocation.
			 */
			ClearPageGCMAFree(page);
			list_del_init(&page->lru);
			page_area_unlock(page);
			continue;
		}

		rcu_read_lock();
		if (!gcma_get_page_unless_zero(page)) {
			page_area_unlock(page);
			rcu_read_unlock();
			/*
			 * The page is being freed but did not reach
			 * the free list.
			 */
			goto again;
		}

		/*
		 * From now on, the page and inode is never freed by page's
		 * refcount and RCU lock.
		 */
		inode = (struct gcma_inode *)page->mapping;
		index = page->index;
		page_area_unlock(page);

		/*
		 * Page is not stored yet since it was allocated. Just retry
		 */
		if (!inode) {
			gcma_put_page(page);
			rcu_read_unlock();
			goto again;
		}

		xa_lock(&inode->pages);
		/*
		 * If the page is not attached to the inode or already is erased,
		 * just retry.
		 */
		if (xa_load(&inode->pages, index) != page) {
			xa_unlock(&inode->pages);
			gcma_put_page(page);
			rcu_read_unlock();
			goto again;
		}

		/*
		 * It's okay to release RCU lock since we verifed the page is
		 * still attached to inode, which means the inode never released
		 * until the page will release the refcount of the inode at
		 * freeing.
		 */
		rcu_read_unlock();

		/*
		 * If someone is holding the refcount, wait on them to finish
		 * the work. In theory, it could cause livelock if someone
		 * repeated to hold/release the refcount in parallel but it
		 * should be extremely rare.
		 *
		 * Expect refcount two from xarray and this function.
		 */
		if (!page_ref_freeze(page, 2)) {
			xa_unlock(&inode->pages);
			gcma_put_page(page);
			goto again;
		}

		__xa_erase(&inode->pages, index);
		xa_unlock(&inode->pages);

		delete_page_from_lru(page);
		page_area_lock(page);
		gcma_free_page(page);
		/*
		 * Isolate the page from free list to prevent further
		 * allocation
		 */
		list_del_init(&page->lru);
		ClearPageGCMAFree(page);
		page_area_unlock(page);

		/*
		 * Release the inode refcount the gcma_put_page was supposed
		 * to do.
		 */
		put_gcma_inode(inode);
	}
	local_irq_enable();
}

void gcma_discard_range(unsigned long start_pfn, unsigned long end_pfn)
{
	int i;
	struct gcma_area *area;
	int nr_area = atomic_read(&nr_gcma_area);

	for (i = 0; i < nr_area; i++) {
		unsigned long s_pfn, e_pfn;

		area = &areas[i];
		if (area->end_pfn < start_pfn)
			continue;

		if (area->start_pfn > end_pfn)
			continue;

		s_pfn = max(start_pfn, area->start_pfn);
		e_pfn = min(end_pfn, area->end_pfn);

		__gcma_discard_range(area, s_pfn, e_pfn);
	}
}

void gcma_free_range(unsigned long start_pfn, unsigned long end_pfn)
{
	unsigned long pfn;
	struct page *page;
	unsigned long scanned = 0;

	VM_BUG_ON(irqs_disabled());

	local_irq_disable();

	for (pfn = start_pfn; pfn <= end_pfn; pfn++) {
		if (!(++scanned % XA_CHECK_SCHED)) {
			local_irq_enable();
			/* let in any pending interrupt */
			cond_resched();
			local_irq_disable();
		}

		page = pfn_to_page(pfn);
		VM_BUG_ON(PageGCMAFree(page));

		page_area_lock(page);
		__gcma_free_page(page);
		page_area_unlock(page);
	}

	local_irq_enable();
}

static void evict_gcma_lru_pages(unsigned long nr_request)
{
	unsigned long nr_evicted = 0;

	while (nr_request) {
		struct page *pages[MAX_EVICT_BATCH];
		int i, nr_pages = 0;
		unsigned long tried = 0;
		unsigned long flags;
		struct page *page, *tmp;

		spin_lock_irqsave(&lru_lock, flags);
		if (list_empty(&gcma_lru)) {
			spin_unlock_irqrestore(&lru_lock, flags);
			return;
		}

		list_for_each_entry_safe_reverse(page, tmp, &gcma_lru, lru) {
			if (tried == MAX_EVICT_BATCH)
				break;
			tried++;
			if (gcma_get_page_unless_zero(page)) {
				list_del_init(&page->lru);
				pages[nr_pages++] = page;
			}
		}
		spin_unlock_irqrestore(&lru_lock, flags);
		nr_request -= min(nr_request, tried);

		/* From now on, pages in the list will never be free */
		for (i = 0; i < nr_pages; i++) {
			struct gcma_inode *inode;
			unsigned long index;

			page = pages[i];
			inode = (struct gcma_inode *)page->mapping;
			index = page->index;

			xa_lock_irqsave(&inode->pages, flags);
			if (xa_load(&inode->pages, index) == page)
				gcma_erase_page(inode, index, page);
			xa_unlock_irqrestore(&inode->pages, flags);
			gcma_put_page(page);
			nr_evicted++;
		}
	}
	atomic64_add(nr_evicted, &gcma_evicted_page);
}

static void evict_gcma_pages(struct work_struct *work)
{
	evict_gcma_lru_pages(MAX_EVICT_BATCH);
}

static DECLARE_WORK(lru_evict_work, evict_gcma_pages);

void gcma_cc_store_page(int hash_id, struct cleancache_filekey key,
			pgoff_t offset, struct page *page)
{
	struct gcma_fs *gcma_fs;
	struct gcma_inode *inode;
	struct page *g_page;
	void *src, *dst;
	bool is_new = false;
	bool workingset = PageWorkingset(page);

	/*
	 * This cleancache function is called under irq disabled so every
	 * locks in this function should take of the irq if they are
	 * used in the non-irqdisabled context.
	 */
	VM_BUG_ON(!irqs_disabled());

find_inode:
	gcma_fs = idr_find(&gcma_fs_idr, hash_id);
	VM_BUG_ON(!gcma_fs);

	inode = find_and_get_gcma_inode(gcma_fs, &key);
	if (!inode) {
		if (!workingset)
			return;
		inode = add_gcma_inode(gcma_fs, &key);
		if (!IS_ERR(inode))
			goto load_page;
		/*
		 * If someone just added new inode under us, retry to find it.
		 */
		if (PTR_ERR(inode) == -EEXIST)
			goto find_inode;
		return;
	}

load_page:
	VM_BUG_ON(!inode);

	xa_lock(&inode->pages);
	g_page = xa_load(&inode->pages, offset);
	if (g_page) {
		if (!workingset) {
			gcma_erase_page(inode, offset, g_page);
			goto out_unlock;
		}
		goto copy;
	}

	if (!workingset)
		goto out_unlock;

	g_page = gcma_alloc_page();
	if (!g_page) {
		schedule_work(&lru_evict_work);
		goto out_unlock;
	}

	if (gcma_store_page(inode, offset, g_page)) {
		gcma_put_page(g_page);
		goto out_unlock;
	}

	gcma_put_page(g_page);
	is_new = true;
copy:
	src = kmap_atomic(page);
	dst = kmap_atomic(g_page);
	memcpy(dst, src, PAGE_SIZE);
	kunmap_atomic(dst);
	kunmap_atomic(src);

	if (is_new)
		add_page_to_lru(g_page);
	else
		rotate_lru_page(g_page);

	atomic64_inc(&gcma_stored_page);
out_unlock:
	xa_unlock(&inode->pages);
	put_gcma_inode(inode);
}

static int gcma_cc_load_page(int hash_id, struct cleancache_filekey key,
			pgoff_t offset, struct page *page)
{
	struct gcma_fs *gcma_fs;
	struct gcma_inode *inode;
	struct page *g_page;
	void *src, *dst;

	VM_BUG_ON(irqs_disabled());

	gcma_fs = idr_find(&gcma_fs_idr, hash_id);
	VM_BUG_ON(!gcma_fs);

	inode = find_and_get_gcma_inode(gcma_fs, &key);
	if (!inode)
		return -1;

	xa_lock_irq(&inode->pages);
	g_page = xa_load(&inode->pages, offset);
	if (!g_page) {
		xa_unlock_irq(&inode->pages);
		put_gcma_inode(inode);
		return -1;
	}

	src = kmap_atomic(g_page);
	dst = kmap_atomic(page);
	memcpy(dst, src, PAGE_SIZE);
	kunmap_atomic(dst);
	kunmap_atomic(src);
	rotate_lru_page(g_page);
	xa_unlock_irq(&inode->pages);

	put_gcma_inode(inode);
	atomic64_inc(&gcma_loaded_page);

	return 0;
}

static void gcma_cc_invalidate_page(int hash_id, struct cleancache_filekey key,
				pgoff_t offset)
{
	struct gcma_fs *gcma_fs;
	struct gcma_inode *inode;
	struct page *g_page;
	unsigned long flags;

	gcma_fs = idr_find(&gcma_fs_idr, hash_id);
	VM_BUG_ON(!gcma_fs);

	inode = find_and_get_gcma_inode(gcma_fs, &key);
	if (!inode)
		return;

	xa_lock_irqsave(&inode->pages, flags);
	g_page = xa_load(&inode->pages, offset);
	if (!g_page)
		goto out;
	gcma_erase_page(inode, offset, g_page);
out:
	xa_unlock_irqrestore(&inode->pages, flags);
	put_gcma_inode(inode);
}

static bool try_empty_inode(struct gcma_inode *inode)
{
	struct page *page;
	unsigned int scanned = 0;
	unsigned long flags;

	XA_STATE(xas, &inode->pages, 0);

	xas_lock_irqsave(&xas, flags);
	xas_for_each(&xas, page, ULONG_MAX) {
		gcma_erase_page(inode, xas.xa_index, page);
		if (++scanned % XA_CHECK_SCHED)
			continue;
		xas_pause(&xas);
		xas_unlock_irqrestore(&xas, flags);
		cond_resched();
		xas_lock_irqsave(&xas, flags);
	}
	xas_unlock_irqrestore(&xas, flags);

	return refcount_reset_if_equal(&inode->ref_count, 1);
}

static struct gcma_inode *__gcma_cc_invalidate_inode(struct gcma_fs *gcma_fs,
					struct cleancache_filekey *key)
{
	struct gcma_inode *inode;

retry:
	inode = find_and_get_gcma_inode(gcma_fs, key);
	if (!inode)
		return NULL;

	if (!try_empty_inode(inode)) {
		put_gcma_inode(inode);
		goto retry;
	}

	return inode;
}

static void gcma_cc_invalidate_inode(int hash_id, struct cleancache_filekey key)
{
	struct gcma_fs *gcma_fs;
	struct gcma_inode *inode;

	gcma_fs = idr_find(&gcma_fs_idr, hash_id);
	VM_BUG_ON(!gcma_fs);

	inode = __gcma_cc_invalidate_inode(gcma_fs, &key);
	if (inode) {
		unsigned long flags;

		spin_lock_irqsave(&gcma_fs->hash_lock, flags);
		__put_gcma_inode(inode);
		spin_unlock_irqrestore(&gcma_fs->hash_lock, flags);
	}
}

static void gcma_cc_invalidate_fs(int hash_id)
{
	struct gcma_fs *gcma_fs;
	struct gcma_inode *inode;
	int cursor, i;
	struct hlist_node *tmp;

	gcma_fs = idr_find(&gcma_fs_idr, hash_id);
	VM_BUG_ON(!gcma_fs);
	VM_BUG_ON(irqs_disabled());

	spin_lock_irq(&gcma_fs->hash_lock);
	hash_for_each_safe(gcma_fs->inode_hash, cursor, tmp, inode, hash) {
		inode = __gcma_cc_invalidate_inode(gcma_fs, &inode->key);
		if (inode)
			__put_gcma_inode(inode);
	}
	spin_unlock_irq(&gcma_fs->hash_lock);

	synchronize_rcu();

	for (i = 0; i < HASH_SIZE(gcma_fs->inode_hash); i++)
		VM_BUG_ON(!hlist_empty(&gcma_fs->inode_hash[i]));

	spin_lock(&gcma_fs_lock);
	idr_remove(&gcma_fs_idr, hash_id);
	spin_unlock(&gcma_fs_lock);

	kfree(gcma_fs);
}

static int gcma_cc_init_fs(size_t page_size)
{
	int hash_id;
	struct gcma_fs *gcma_fs;

	if (atomic_read(&nr_gcma_area) == 0)
		return -ENOMEM;

	if (page_size != PAGE_SIZE)
		return -EOPNOTSUPP;

	gcma_fs = kzalloc(sizeof(struct gcma_fs), GFP_KERNEL);
	if (!gcma_fs)
		return -ENOMEM;

	spin_lock_init(&gcma_fs->hash_lock);
	hash_init(gcma_fs->inode_hash);

	idr_preload(GFP_KERNEL);

	spin_lock(&gcma_fs_lock);
	hash_id = idr_alloc(&gcma_fs_idr, gcma_fs, 0, 0, GFP_NOWAIT);
	spin_unlock(&gcma_fs_lock);

	idr_preload_end();

	if (hash_id < 0) {
		pr_warn("too many gcma instances\n");
		kfree(gcma_fs);
	} else
		pr_info("Created GCMA[%d] instance\n", hash_id);

	return hash_id;
}

static int gcma_cc_init_shared_fs(uuid_t *uuid, size_t pagesize)
{
	return -1;
}

struct cleancache_ops gcma_cleancache_ops = {
	.init_fs = gcma_cc_init_fs,
	.init_shared_fs = gcma_cc_init_shared_fs,
	.get_page = gcma_cc_load_page,
	.put_page = gcma_cc_store_page,
	.invalidate_page = gcma_cc_invalidate_page,
	.invalidate_inode = gcma_cc_invalidate_inode,
	.invalidate_fs = gcma_cc_invalidate_fs,
};

#ifdef CONFIG_SYSFS
/*
 * This all compiles without CONFIG_SYSFS, but is a waste of space.
 */

#define GCMA_ATTR_RO(_name) \
	static struct kobj_attribute _name##_attr = __ATTR_RO(_name)

static ssize_t stored_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%llu\n", (u64)atomic64_read(&gcma_stored_page));
}
GCMA_ATTR_RO(stored);

static ssize_t loaded_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%llu\n", (u64)atomic64_read(&gcma_loaded_page));
}
GCMA_ATTR_RO(loaded);

static ssize_t evicted_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%llu\n", (u64)atomic64_read(&gcma_evicted_page));
}
GCMA_ATTR_RO(evicted);

static ssize_t cached_show(struct kobject *kobj,
				    struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%llu\n", (u64)atomic64_read(&gcma_cached_page));
}
GCMA_ATTR_RO(cached);

static struct attribute *gcma_attrs[] = {
	&stored_attr.attr,
	&loaded_attr.attr,
	&evicted_attr.attr,
	&cached_attr.attr,
	NULL,
};

static const struct attribute_group gcma_attr_group = {
	.attrs = gcma_attrs,
	.name = "gcma",
};
#endif

static int __init gcma_init(void)
{
	int err = -ENOMEM;

	slab_gcma_inode = KMEM_CACHE(gcma_inode, 0);
	if (!slab_gcma_inode)
		goto out;

#ifdef CONFIG_SYSFS
	err = sysfs_create_group(mm_kobj, &gcma_attr_group);
	if (err) {
		pr_err("failed to register sysfs\n");
		kmem_cache_destroy(slab_gcma_inode);
		goto out;
	}
#endif

	cleancache_register_ops(&gcma_cleancache_ops);

	return 0;
out:
	return err;
}
module_init(gcma_init);
