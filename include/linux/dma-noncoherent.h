/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_DMA_NONCOHERENT_H
#define _LINUX_DMA_NONCOHERENT_H 1

#include <linux/dma-mapping.h>
#include <linux/slab.h>

/*
 * Check whether the given size, assuming it is for a kmalloc()'ed object, is
 * safe for non-coherent DMA or needs bouncing.
 */
static inline bool dma_kmalloc_needs_bounce(struct device *dev, size_t size,
					    enum dma_data_direction dir)
{
	/*
	 * No need for bouncing if coherent DMA or the direction is
	 * DMA_TO_DEVICE.
	 */
	if (!IS_ENABLED(CONFIG_DMA_BOUNCE_UNALIGNED_KMALLOC) ||
	    dir == DMA_TO_DEVICE || dev_is_dma_coherent(dev))
		return false;

	/*
	 * Larger kmalloc() sizes are guaranteed to be aligned to
	 * ARCH_DMA_MINALIGN.
	 */
	if (size >= 2 * ARCH_DMA_MINALIGN ||
	    IS_ALIGNED(kmalloc_size_roundup(size), dma_get_cache_alignment()))
		return false;

	return true;
}

void *arch_dma_alloc(struct device *dev, size_t size, dma_addr_t *dma_handle,
		gfp_t gfp, unsigned long attrs);
void arch_dma_free(struct device *dev, size_t size, void *cpu_addr,
		dma_addr_t dma_addr, unsigned long attrs);

#ifdef CONFIG_DMA_NONCOHERENT_MMAP
int arch_dma_mmap(struct device *dev, struct vm_area_struct *vma,
		void *cpu_addr, dma_addr_t dma_addr, size_t size,
		unsigned long attrs);
#else
#define arch_dma_mmap NULL
#endif /* CONFIG_DMA_NONCOHERENT_MMAP */

#ifdef CONFIG_DMA_NONCOHERENT_CACHE_SYNC
void arch_dma_cache_sync(struct device *dev, void *vaddr, size_t size,
		enum dma_data_direction direction);
#else
#define arch_dma_cache_sync NULL
#endif /* CONFIG_DMA_NONCOHERENT_CACHE_SYNC */

#ifdef CONFIG_ARCH_HAS_SYNC_DMA_FOR_DEVICE
void arch_sync_dma_for_device(struct device *dev, phys_addr_t paddr,
		size_t size, enum dma_data_direction dir);
#else
static inline void arch_sync_dma_for_device(struct device *dev,
		phys_addr_t paddr, size_t size, enum dma_data_direction dir)
{
}
#endif /* ARCH_HAS_SYNC_DMA_FOR_DEVICE */

#ifdef CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU
void arch_sync_dma_for_cpu(struct device *dev, phys_addr_t paddr,
		size_t size, enum dma_data_direction dir);
#else
static inline void arch_sync_dma_for_cpu(struct device *dev,
		phys_addr_t paddr, size_t size, enum dma_data_direction dir)
{
}
#endif /* ARCH_HAS_SYNC_DMA_FOR_CPU */

#ifdef CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU_ALL
void arch_sync_dma_for_cpu_all(struct device *dev);
#else
static inline void arch_sync_dma_for_cpu_all(struct device *dev)
{
}
#endif /* CONFIG_ARCH_HAS_SYNC_DMA_FOR_CPU_ALL */

#endif /* _LINUX_DMA_NONCOHERENT_H */
